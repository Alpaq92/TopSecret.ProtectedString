using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace TopSecret.Analyzers;

/// <summary>
/// Flags the most common patterns where the plaintext made available
/// inside a <c>ProtectedString.Access(...)</c> callback is copied into
/// a managed object that survives the callback — at which point the
/// library's wipe-on-return guarantee no longer applies.
/// </summary>
/// <remarks>
/// <para>
/// The C# language cannot prevent intentional copying — a determined
/// caller can always write <c>new string(plain)</c> or
/// <c>plain.ToString()</c>, and once the bytes have been hashed into a
/// <see cref="string"/> the runtime may intern, deduplicate, or copy
/// them across GC cycles in ways nothing in user code can erase. The
/// analyzer's job is to make the accidental case loud at build time so
/// the deliberate case has to be acknowledged with a suppression.
/// </para>
/// <para>
/// Three diagnostics ship:
/// </para>
/// <list type="bullet">
///   <item><b>TPS001 — plaintext copied to <c>string</c>.</b> Triggered
///   by <c>new string(plain)</c>, <c>plain.ToString()</c>,
///   <c>plain.AsSpan().ToString()</c>, <c>string.Concat(...,
///   plain, ...)</c>, <c>string.Create(..., plain, ...)</c>, or
///   <c>Encoding.*.GetString(...)</c> over the plaintext (or a span
///   over it) inside an <c>Access</c> callback.</item>
///   <item><b>TPS002 — plaintext array captured outside callback.</b>
///   Triggered when the <c>Action&lt;char[]&gt;</c> overload's
///   parameter is assigned to a captured local, field, or property —
///   the array is zeroed when the callback returns, so any retained
///   reference observes garbage at best and is a use-after-free
///   surprise at worst.</item>
///   <item><b>TPS003 — plaintext copied into a new array.</b> Triggered
///   by <c>plain.ToArray()</c> (array or span parameter) inside an
///   <c>Access</c> callback — the copy is an ordinary heap array the
///   library never zeroes, and its reference escapes trivially.</item>
/// </list>
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EscapingPlaintextAnalyzer : DiagnosticAnalyzer
{
    public const string CopyToStringDiagnosticId = "TPS001";
    public const string CapturedArrayDiagnosticId = "TPS002";
    public const string CopyToArrayDiagnosticId = "TPS003";

    private const string ProtectedStringMetadataName = "TopSecret.ProtectedString";
    private const string AccessMethodName = "Access";

    private static readonly DiagnosticDescriptor CopyToStringRule = new(
        id: CopyToStringDiagnosticId,
        title: "Plaintext copied into a managed string inside ProtectedString.Access",
        messageFormat:
            "Copying the plaintext '{0}' into a managed string defeats ProtectedString's wipe-on-return " +
            "guarantee — strings are immutable, may be interned, and cannot be reliably erased from " +
            "memory. If you genuinely need the value as a string for an external API, suppress with " +
            "#pragma warning disable TPS001 and document why.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "Once the plaintext leaves the Access callback as a managed System.String, it is on the " +
            "regular GC heap until reclaimed and may be interned or copied at any time. The library " +
            "cannot zero a string. Prefer purpose-built sinks (CopyTo, WriteUtf8To) or perform the " +
            "string-shaped operation inside the callback.");

    private static readonly DiagnosticDescriptor CapturedArrayRule = new(
        id: CapturedArrayDiagnosticId,
        title: "ProtectedString.Access plaintext array reference escapes the callback",
        messageFormat:
            "The plaintext array '{0}' is being assigned to '{1}', which outlives the Access callback. " +
            "ProtectedString zeroes the array when the callback returns, so the retained reference " +
            "observes a buffer of zeros at best. Prefer the ReadOnlySpan<char> overload of Access — " +
            "ReadOnlySpan is a ref struct that the compiler refuses to let escape.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "The Action<char[]> overload of ProtectedString.Access hands the callback a heap-allocated " +
            "char[]. Anything that retains a reference to that array past the lambda body — captured " +
            "locals, fields, properties — sees the post-zero state. Even if it weren't zeroed, " +
            "retaining the reference is a leak the library cannot defend against.");

    private static readonly DiagnosticDescriptor CopyToArrayRule = new(
        id: CopyToArrayDiagnosticId,
        title: "Plaintext copied into a new array inside ProtectedString.Access",
        messageFormat:
            "Calling ToArray() on the plaintext '{0}' copies it into a new heap array that " +
            "ProtectedString never zeroes — the copy silently outlives the wipe-on-return guarantee, " +
            "and its reference can escape the callback freely. Operate on the provided buffer in " +
            "place, or if a copy is genuinely required, zero it yourself in a finally block and " +
            "suppress with #pragma warning disable TPS003.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "ToArray() allocates an ordinary managed array and copies the plaintext into it. The " +
            "library only wipes the buffer it handed to the callback; the copy keeps the secret on " +
            "the GC heap until reclaimed, unwiped, and — unlike a ReadOnlySpan — nothing stops the " +
            "reference from being captured past the callback. Prefer working against the provided " +
            "span/array directly, or the purpose-built sinks (CopyTo, WriteUtf8To).");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(CopyToStringRule, CapturedArrayRule, CopyToArrayRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeObjectCreation, SyntaxKind.ObjectCreationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var creation = (ObjectCreationExpressionSyntax)context.Node;

        // We only care about `new string(...)`.
        var typeSymbol = context.SemanticModel.GetSymbolInfo(creation.Type, context.CancellationToken).Symbol as INamedTypeSymbol;
        if (typeSymbol is null || typeSymbol.SpecialType != SpecialType.System_String) return;

        if (creation.ArgumentList is null) return;
        foreach (var arg in creation.ArgumentList.Arguments)
        {
            if (TryGetAccessParameterName(arg.Expression, context, out var paramName))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToStringRule, creation.GetLocation(), paramName));
                return;
            }
        }
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;
        if (invocation.Expression is not MemberAccessExpressionSyntax member) return;

        // <param>.ToString() / <param>.ToArray() (or a span over it) — same
        // detection shape, different escape: ToString is an unwipeable
        // managed string (TPS001), ToArray a never-zeroed heap copy (TPS003).
        if (member.Name.Identifier.ValueText is "ToString" or "ToArray" &&
            invocation.ArgumentList.Arguments.Count == 0 &&
            TryGetPlaintextParameterName(member.Expression, context, out var copyTarget))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                member.Name.Identifier.ValueText == "ToString" ? CopyToStringRule : CopyToArrayRule,
                invocation.GetLocation(), copyTarget));
            return;
        }

        // string.Concat(... plain ...), string.Create(len, plain, ...) and
        // friends — surface the most common accidental-stringification
        // overloads. Anything that's a static method on System.String or
        // System.Text.StringBuilder which receives the plaintext arg by
        // value triggers TPS001.
        var methodSymbol = context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol as IMethodSymbol;
        if (methodSymbol is null) return;

        var containingType = methodSymbol.ContainingType;
        if (containingType is null) return;

        // Encoding.*.GetString(...) — decoding the plaintext (or a span
        // over it, e.g. MemoryMarshal.AsBytes(plain)) straight into a
        // managed string is the same escape class as new string(plain).
        if (methodSymbol.Name == "GetString" && IsOrDerivesFromSystemTextEncoding(containingType))
        {
            foreach (var arg in invocation.ArgumentList.Arguments)
            {
                if (TryGetPlaintextParameterName(arg.Expression, context, out var decodedArg))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        CopyToStringRule, invocation.GetLocation(), decodedArg));
                    return;
                }
            }
            return;
        }

        bool isStringSink =
            containingType.SpecialType == SpecialType.System_String ||
            containingType.ToDisplayString() == "System.Text.StringBuilder";
        if (!isStringSink) return;

        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (TryGetAccessParameterName(arg.Expression, context, out var sinkArg))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToStringRule, invocation.GetLocation(), sinkArg));
                return;
            }
        }
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;

        // Only flag when the right-hand side is the lambda parameter (or a
        // direct alias like `(plain)`). Pattern: target = plain.
        if (!TryGetAccessParameterName(assignment.Right, context, out var paramName)) return;

        // The parameter must be a char[] (the obsolete Access overload).
        // Spans are ref structs and the compiler enforces non-escape — no
        // assignment is possible. Skip any case where the parameter is a
        // ref struct.
        if (assignment.Right is IdentifierNameSyntax id)
        {
            var symbol = context.SemanticModel.GetSymbolInfo(id, context.CancellationToken).Symbol;
            if (symbol is IParameterSymbol p && p.Type is INamedTypeSymbol pt && pt.IsRefLikeType)
            {
                return;
            }
        }

        // The left-hand side must be something that survives the callback —
        // a field, a property, or a captured local declared outside the
        // lambda body. (Locals declared inside the lambda are fine; they die
        // with the frame.)
        var lhsSymbol = context.SemanticModel.GetSymbolInfo(assignment.Left, context.CancellationToken).Symbol;
        if (lhsSymbol is null) return;

        bool escapes = false;
        string lhsName = lhsSymbol.Name;
        switch (lhsSymbol)
        {
            case IFieldSymbol:
            case IPropertySymbol:
                escapes = true;
                break;

            case ILocalSymbol local:
                // Captured local: declared outside the enclosing lambda.
                if (IsDeclaredOutsideEnclosingLambda(local, assignment, context.CancellationToken))
                {
                    escapes = true;
                }
                break;
        }

        if (escapes)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                CapturedArrayRule, assignment.GetLocation(), paramName, lhsName));
        }
    }

    /// <summary>
    /// Walks up the syntax tree from <paramref name="expression"/> looking
    /// for an enclosing scope (lambda or local function) that declares
    /// <paramref name="expression"/>'s parameter symbol, then keeps
    /// walking outward to find a lambda passed to
    /// <c>ProtectedString.Access(...)</c>. Returns the parameter's
    /// identifier name on a hit; otherwise <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Local-function support lets us flag patterns like
    /// <c>ps.Access(p =&gt; { void inner(char[] more) =&gt; new string(more); ... })</c>
    /// — the inner local function's body executes synchronously inside
    /// the Access window, so a leak there is the same kind of leak as a
    /// direct lambda-body leak. A local function defined <i>outside</i>
    /// any Access call and passed by name (<c>ps.Access(Inner)</c>) is
    /// still not covered: catching that requires a cross-tree reference
    /// search, which is documented as a known limitation in the
    /// analyzer's class doc.
    /// </remarks>
    private static bool TryGetAccessParameterName(
        ExpressionSyntax expression,
        SyntaxNodeAnalysisContext context,
        out string parameterName)
    {
        parameterName = string.Empty;

        // Strip parentheses: `(plain)` should bind the same as `plain`.
        while (expression is ParenthesizedExpressionSyntax paren)
        {
            expression = paren.Expression;
        }

        if (expression is not IdentifierNameSyntax identifier) return false;

        var symbolInfo = context.SemanticModel.GetSymbolInfo(identifier, context.CancellationToken);
        if (symbolInfo.Symbol is not IParameterSymbol parameter) return false;

        // Walk up to the scope that declares the parameter — either a
        // lambda or a local function. Anything else (regular method, ctor)
        // falls outside our analyzer's scope and we bail.
        SyntaxNode? declaringScope = identifier.Parent;
        while (declaringScope is not null)
        {
            if (declaringScope is LambdaExpressionSyntax lambda &&
                LambdaDeclaresParameter(lambda, parameter))
            {
                break;
            }
            if (declaringScope is LocalFunctionStatementSyntax localFn &&
                LocalFunctionDeclaresParameter(localFn, parameter))
            {
                break;
            }
            declaringScope = declaringScope.Parent;
        }
        if (declaringScope is null) return false;

        // Walk further outward looking for a lambda that's an argument to
        // ProtectedString.Access(...). The declaring scope itself counts
        // (lambda case); a local function defined inside an Access lambda
        // walks out to that lambda and matches; a local function defined
        // outside any such lambda walks to a method/ctor body and bails.
        for (SyntaxNode? walker = declaringScope; walker is not null; walker = walker.Parent)
        {
            if (walker is LambdaExpressionSyntax candidate &&
                IsArgumentToProtectedStringAccessInvocation(candidate, context))
            {
                parameterName = parameter.Name;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Like <see cref="TryGetAccessParameterName"/>, but additionally sees
    /// through the small set of well-known "span over the same memory"
    /// wrappers — <c>plain.AsSpan(...)</c>,
    /// <c>MemoryMarshal.AsBytes(...)</c>, and
    /// <c>MemoryMarshal.Cast&lt;TFrom, TTo&gt;(...)</c> — so that e.g.
    /// <c>Encoding.UTF8.GetString(MemoryMarshal.AsBytes(plain))</c> still
    /// resolves to the Access plaintext parameter.
    /// </summary>
    /// <remarks>
    /// Anything else (user helpers, slicing arithmetic, LINQ chains) is
    /// deliberately not chased: consistent with the analyzer's bias, we
    /// prefer a false negative on exotic dataflow over flagging a
    /// legitimate sink. Each wrapper is verified by symbol (containing
    /// type <c>System.MemoryExtensions</c> /
    /// <c>System.Runtime.InteropServices.MemoryMarshal</c>) so user
    /// methods that merely share the name cannot trigger.
    /// </remarks>
    private static bool TryGetPlaintextParameterName(
        ExpressionSyntax expression,
        SyntaxNodeAnalysisContext context,
        out string parameterName)
    {
        while (true)
        {
            if (TryGetAccessParameterName(expression, context, out parameterName))
            {
                return true;
            }

            while (expression is ParenthesizedExpressionSyntax paren)
            {
                expression = paren.Expression;
            }

            if (expression is not InvocationExpressionSyntax invocation ||
                invocation.Expression is not MemberAccessExpressionSyntax member)
            {
                return false;
            }

            switch (member.Name.Identifier.ValueText)
            {
                case "AsSpan":
                    // Reduced extension form: `plain.AsSpan(...)` — the
                    // wrapped expression is the receiver.
                    if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol
                            is not IMethodSymbol asSpan ||
                        asSpan.ContainingType?.ToDisplayString() != "System.MemoryExtensions")
                    {
                        return false;
                    }
                    expression = member.Expression;
                    continue;

                case "AsBytes":
                case "Cast":
                    // Static form: `MemoryMarshal.AsBytes(x)` /
                    // `MemoryMarshal.Cast<TFrom, TTo>(x)` — the wrapped
                    // expression is the sole argument.
                    if (invocation.ArgumentList.Arguments.Count != 1) return false;
                    if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol
                            is not IMethodSymbol marshal ||
                        marshal.ContainingType?.ToDisplayString() != "System.Runtime.InteropServices.MemoryMarshal")
                    {
                        return false;
                    }
                    expression = invocation.ArgumentList.Arguments[0].Expression;
                    continue;

                default:
                    return false;
            }
        }
    }

    private static bool IsOrDerivesFromSystemTextEncoding(INamedTypeSymbol type)
    {
        // Encoding.UTF8.GetString(...) usually binds to a member declared
        // on System.Text.Encoding itself, but the virtual overloads may
        // resolve to an override on a concrete subclass (UTF8Encoding,
        // UnicodeEncoding, user encodings) — walk the base chain.
        for (INamedTypeSymbol? cursor = type; cursor is not null; cursor = cursor.BaseType)
        {
            if (cursor.ToDisplayString() == "System.Text.Encoding") return true;
        }
        return false;
    }

    private static bool LambdaDeclaresParameter(LambdaExpressionSyntax lambda, IParameterSymbol parameter)
    {
        // Cheap check by name: the parameter must appear in the lambda's
        // parameter list. The semantic model already pinned the parameter's
        // ContainingSymbol; we use name as a fast filter and let the caller's
        // overall flow rely on SemanticModel for correctness.
        switch (lambda)
        {
            case SimpleLambdaExpressionSyntax simple:
                return simple.Parameter.Identifier.ValueText == parameter.Name;
            case ParenthesizedLambdaExpressionSyntax parenthesized:
                foreach (var p in parenthesized.ParameterList.Parameters)
                {
                    if (p.Identifier.ValueText == parameter.Name) return true;
                }
                return false;
            default:
                return false;
        }
    }

    private static bool LocalFunctionDeclaresParameter(
        LocalFunctionStatementSyntax localFn,
        IParameterSymbol parameter)
    {
        // Same cheap name-based filter as LambdaDeclaresParameter; the
        // SemanticModel-bound IParameterSymbol guarantees that any name
        // collision in the same scope would already have flagged earlier.
        foreach (var p in localFn.ParameterList.Parameters)
        {
            if (p.Identifier.ValueText == parameter.Name) return true;
        }
        return false;
    }

    private static bool IsArgumentToProtectedStringAccessInvocation(
        LambdaExpressionSyntax lambda,
        SyntaxNodeAnalysisContext context)
    {
        if (lambda.Parent is not ArgumentSyntax argument) return false;
        if (argument.Parent is not ArgumentListSyntax argList) return false;
        if (argList.Parent is not InvocationExpressionSyntax invocation) return false;

        var symbol = context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol as IMethodSymbol;
        if (symbol is null) return false;

        if (symbol.Name != AccessMethodName) return false;

        // ContainingType must be ProtectedString. Match by metadata name
        // (namespace + type) so renames in user code can't masquerade.
        var containing = symbol.ContainingType;
        if (containing is null) return false;
        return containing.ToDisplayString() == ProtectedStringMetadataName;
    }

    private static bool IsDeclaredOutsideEnclosingLambda(
        ILocalSymbol local,
        SyntaxNode reference,
        System.Threading.CancellationToken cancellationToken)
    {
        var declaringRef = local.DeclaringSyntaxReferences;
        if (declaringRef.Length == 0) return false;
        var declarationNode = declaringRef[0].GetSyntax(cancellationToken);

        // Find the smallest lambda enclosing the reference.
        SyntaxNode? cursor = reference.Parent;
        LambdaExpressionSyntax? enclosing = null;
        while (cursor is not null)
        {
            if (cursor is LambdaExpressionSyntax l) { enclosing = l; break; }
            cursor = cursor.Parent;
        }
        if (enclosing is null) return false;

        // Local is "outside" if its declaration is NOT a descendant of the lambda.
        return !enclosing.Span.Contains(declarationNode.Span);
    }
}
