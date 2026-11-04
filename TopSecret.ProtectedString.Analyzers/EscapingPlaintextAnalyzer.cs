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
///   <c>plain.Slice(..).ToString()</c>, <c>plain[..n].ToString()</c>,
///   string interpolation (<c>$"{plain}"</c>), <c>string.Concat(...,
///   plain, ...)</c>, <c>string.Create(..., plain, ...)</c>,
///   <c>StringBuilder.Append(plain)</c>, <c>Encoding.*.GetString(...)</c>
///   or <c>Convert.ToBase64String(...)</c> / <c>Convert.ToHexString(...)</c>
///   over the plaintext (or a span over it) inside an <c>Access</c>
///   callback.</item>
///   <item><b>TPS002 — plaintext array escapes the callback.</b>
///   Triggered when the <c>Action&lt;char[]&gt;</c> /
///   <c>Func&lt;char[], T&gt;</c> overload's parameter is assigned to a
///   captured local, field, property or collection slot, returned from
///   the callback, or stored into a collection (<c>list.Add(plain)</c>) —
///   the array is zeroed when the callback returns, so any retained
///   reference observes garbage at best and is a use-after-free surprise
///   at worst.</item>
///   <item><b>TPS003 — plaintext copied into a new array.</b> Triggered
///   by <c>plain.ToArray()</c> (array or span parameter, including over
///   a slice), <c>Encoding.*.GetBytes(plain)</c> overloads that return a
///   fresh <c>byte[]</c>, or range-indexing an array parameter
///   (<c>plain[..n]</c>) inside an <c>Access</c> callback — the copy is an
///   ordinary heap array the library never zeroes, and its reference
///   escapes trivially.</item>
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
            "The plaintext array '{0}' escapes the Access callback through {1}. " +
            "ProtectedString zeroes the array when the callback returns, so the retained reference " +
            "observes a buffer of zeros at best. Prefer the ReadOnlySpan<char> overload of Access — " +
            "ReadOnlySpan is a ref struct that the compiler refuses to let escape.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "The Action<char[]> and Func<char[], T> overloads of ProtectedString.Access hand the " +
            "callback a heap-allocated char[]. Anything that retains a reference to that array past " +
            "the lambda body — captured locals, fields, properties, collections, or the callback's " +
            "own return value — sees the post-zero state. Even if it weren't zeroed, retaining the " +
            "reference is a leak the library cannot defend against.");

    private static readonly DiagnosticDescriptor CopyToArrayRule = new(
        id: CopyToArrayDiagnosticId,
        title: "Plaintext copied into a new array inside ProtectedString.Access",
        messageFormat:
            "{1} the plaintext '{0}' copies it into a new heap array that " +
            "ProtectedString never zeroes — the copy silently outlives the wipe-on-return guarantee, " +
            "and its reference can escape the callback freely. Operate on the provided buffer in " +
            "place, or if a copy is genuinely required, zero it yourself in a finally block and " +
            "suppress with #pragma warning disable TPS003.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description:
            "ToArray(), Encoding.GetBytes(...) and range-indexing an array (plain[..n]) all allocate " +
            "an ordinary managed array and copy the plaintext into it. The library only wipes the " +
            "buffer it handed to the callback; the copy keeps the secret on the GC heap until " +
            "reclaimed, unwiped, and — unlike a ReadOnlySpan — nothing stops the reference from " +
            "being captured past the callback. Prefer working against the provided span/array " +
            "directly, or the purpose-built sinks (CopyTo, WriteUtf8To).");

    /// <summary>
    /// Instance methods on <see cref="System.Collections.IEnumerable"/>
    /// implementations that store their argument for later retrieval.
    /// Passing the plaintext array to one of these parks the reference
    /// in a collection that (almost always) outlives the callback.
    /// </summary>
    private static readonly ImmutableHashSet<string> s_collectionStoreMethodNames = ImmutableHashSet.Create(
        "Add", "TryAdd", "Insert", "Enqueue", "Push", "AddFirst", "AddLast", "AddBefore", "AddAfter");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(CopyToStringRule, CapturedArrayRule, CopyToArrayRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(
            AnalyzeObjectCreation,
            SyntaxKind.ObjectCreationExpression,
            SyntaxKind.ImplicitObjectCreationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
        context.RegisterSyntaxNodeAction(AnalyzeInterpolatedString, SyntaxKind.InterpolatedStringExpression);
        context.RegisterSyntaxNodeAction(AnalyzeElementAccess, SyntaxKind.ElementAccessExpression);
        context.RegisterSyntaxNodeAction(AnalyzeReturnStatement, SyntaxKind.ReturnStatement);
        context.RegisterSyntaxNodeAction(
            AnalyzeLambda,
            SyntaxKind.SimpleLambdaExpression,
            SyntaxKind.ParenthesizedLambdaExpression);
    }

    private static void AnalyzeObjectCreation(SyntaxNodeAnalysisContext context)
    {
        var creation = (BaseObjectCreationExpressionSyntax)context.Node;

        // We only care about `new string(...)` / `string s = new(...)`.
        var type = context.SemanticModel.GetTypeInfo(creation, context.CancellationToken).Type;
        if (type is null || type.SpecialType != SpecialType.System_String) return;

        if (creation.ArgumentList is null) return;
        foreach (var arg in creation.ArgumentList.Arguments)
        {
            // Span-aware: `new string(plain.AsSpan(0, 4))` and
            // `new string(plain[..n])` copy the same bytes as `new string(plain)`.
            if (TryGetPlaintextParameterName(arg.Expression, context, out var paramName))
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

        // <param>.ToString() / <param>.ToArray() (or a span / slice over
        // it) — same detection shape, different escape: ToString is an
        // unwipeable managed string (TPS001), ToArray a never-zeroed heap
        // copy (TPS003).
        if (invocation.Expression is MemberAccessExpressionSyntax member &&
            member.Name.Identifier.ValueText is "ToString" or "ToArray" &&
            invocation.ArgumentList.Arguments.Count == 0 &&
            TryGetPlaintextParameterName(member.Expression, context, out var copyTarget))
        {
            context.ReportDiagnostic(member.Name.Identifier.ValueText == "ToString"
                ? Diagnostic.Create(CopyToStringRule, invocation.GetLocation(), copyTarget)
                : Diagnostic.Create(CopyToArrayRule, invocation.GetLocation(), copyTarget, "Calling ToArray() on"));
            return;
        }

        var methodSymbol = context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol as IMethodSymbol;
        if (methodSymbol is null) return;

        var containingType = methodSymbol.ContainingType;
        if (containingType is null) return;

        if (IsOrDerivesFromSystemTextEncoding(containingType))
        {
            // Encoding.*.GetString(...) — decoding the plaintext (or a
            // span over it, e.g. MemoryMarshal.AsBytes(plain)) straight
            // into a managed string is the same escape class as
            // new string(plain).
            if (methodSymbol.Name == "GetString" &&
                TryFindPlaintextArgument(invocation.ArgumentList, context, out var decodedArg))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToStringRule, invocation.GetLocation(), decodedArg));
                return;
            }

            // Encoding.*.GetBytes(plain) / GetBytes(plain, index, count)
            // — the overloads that *return* a byte[] hand back a fresh
            // heap copy of the secret. The overloads that write into a
            // caller-supplied buffer (returning int) are the documented
            // safe pattern and must stay clean.
            if (methodSymbol.Name == "GetBytes" &&
                methodSymbol.ReturnType is IArrayTypeSymbol &&
                TryFindPlaintextArgument(invocation.ArgumentList, context, out var encodedArg))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToArrayRule, invocation.GetLocation(), encodedArg, "Calling Encoding.GetBytes(...) on"));
                return;
            }

            return;
        }

        // Convert.ToBase64String(...) / Convert.ToHexString(...) and any
        // other string-returning System.Convert method: a textual
        // re-encoding of the secret is still the secret in a string.
        if (containingType.ToDisplayString() == "System.Convert" &&
            methodSymbol.ReturnType.SpecialType == SpecialType.System_String &&
            TryFindPlaintextArgument(invocation.ArgumentList, context, out var convertedArg))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                CopyToStringRule, invocation.GetLocation(), convertedArg));
            return;
        }

        // string.Concat(... plain ...), string.Create(len, plain, ...),
        // sb.Append(plain) and friends — surface the most common
        // accidental-stringification overloads. Anything that's a method
        // on System.String or System.Text.StringBuilder which receives
        // the plaintext (or a span over it) by value triggers TPS001.
        bool isStringSink =
            containingType.SpecialType == SpecialType.System_String ||
            containingType.ToDisplayString() == "System.Text.StringBuilder";
        if (isStringSink)
        {
            if (TryFindPlaintextArgument(invocation.ArgumentList, context, out var sinkArg))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToStringRule, invocation.GetLocation(), sinkArg));
            }
            return;
        }

        // list.Add(plain), queue.Enqueue(plain), ... — storing the
        // char[] parameter itself in a collection retains the reference
        // past the callback exactly like `field = plain` does.
        if (!methodSymbol.IsStatic &&
            s_collectionStoreMethodNames.Contains(methodSymbol.Name) &&
            ImplementsIEnumerable(containingType))
        {
            foreach (var arg in invocation.ArgumentList.Arguments)
            {
                if (TryResolveAccessParameter(arg.Expression, context, out var parameter, out _) &&
                    parameter!.Type is IArrayTypeSymbol)
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        CapturedArrayRule,
                        invocation.GetLocation(),
                        parameter.Name,
                        $"the argument to '{containingType.Name}.{methodSymbol.Name}'"));
                    return;
                }
            }
        }
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;

        // Only flag when the right-hand side is the lambda parameter (or a
        // direct alias like `(plain)`). Pattern: target = plain.
        if (!TryResolveAccessParameter(assignment.Right, context, out var parameter, out var accessLambda)) return;

        // The parameter must be a char[] (the obsolete Access overload).
        // Spans are ref structs and the compiler enforces non-escape — no
        // assignment is possible. Skip any case where the parameter is a
        // ref struct.
        if (parameter!.Type is not IArrayTypeSymbol) return;

        // The left-hand side must be something that survives the callback —
        // a field, a property, a collection slot, or a captured local
        // declared outside the Access lambda. (Locals declared inside the
        // Access lambda are fine; they die with the frame — even when the
        // assignment happens in a nested lambda.)
        bool escapes = false;
        string lhsName;

        if (assignment.Left is ElementAccessExpressionSyntax element &&
            context.SemanticModel.GetSymbolInfo(element, context.CancellationToken).Symbol is null)
        {
            // Array element store (`slots[0] = plain`) — arrays have no
            // indexer symbol, so judge by the receiver instead.
            var receiver = context.SemanticModel.GetSymbolInfo(element.Expression, context.CancellationToken).Symbol;
            if (receiver is null) return;
            lhsName = receiver.Name + "[]";
            escapes = receiver is not ILocalSymbol receiverLocal ||
                      IsDeclaredOutside(receiverLocal, accessLambda!, context.CancellationToken);
        }
        else
        {
            var lhsSymbol = context.SemanticModel.GetSymbolInfo(assignment.Left, context.CancellationToken).Symbol;
            if (lhsSymbol is null) return;
            lhsName = lhsSymbol.Name;

            switch (lhsSymbol)
            {
                case IFieldSymbol:
                case IPropertySymbol:
                    escapes = true;
                    break;

                case ILocalSymbol local:
                    // Captured local: declared outside the Access lambda.
                    escapes = IsDeclaredOutside(local, accessLambda!, context.CancellationToken);
                    break;
            }
        }

        if (escapes)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                CapturedArrayRule, assignment.GetLocation(), parameter.Name, $"assignment to '{lhsName}'"));
        }
    }

    private static void AnalyzeInterpolatedString(SyntaxNodeAnalysisContext context)
    {
        var interpolated = (InterpolatedStringExpressionSyntax)context.Node;

        // $"{plain}" / $"{plain[..n]}" — the interpolation handler
        // appends the chars into a string it hands back; same escape as
        // string.Concat. `$"{plain.Length}"` is not a plaintext flow and
        // falls out of TryGetPlaintextParameterName naturally.
        foreach (var content in interpolated.Contents)
        {
            if (content is InterpolationSyntax interpolation &&
                TryGetPlaintextParameterName(interpolation.Expression, context, out var paramName))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToStringRule, interpolation.GetLocation(), paramName));
                return;
            }
        }
    }

    private static void AnalyzeElementAccess(SyntaxNodeAnalysisContext context)
    {
        var access = (ElementAccessExpressionSyntax)context.Node;

        // `plain[..n]` on a char[] compiles to RuntimeHelpers.GetSubArray:
        // a fresh heap array holding a copy of the secret. On a span the
        // same syntax is just a re-slice (no copy) — that case is seen
        // through by TryGetPlaintextParameterName instead.
        if (!IsRangeIndex(access)) return;
        if (!TryGetPlaintextParameterName(access.Expression, context, out var paramName)) return;

        var receiverType = context.SemanticModel.GetTypeInfo(access.Expression, context.CancellationToken).Type;
        if (receiverType is not IArrayTypeSymbol) return;

        context.ReportDiagnostic(Diagnostic.Create(
            CopyToArrayRule, access.GetLocation(), paramName, "Range-indexing"));
    }

    private static void AnalyzeReturnStatement(SyntaxNodeAnalysisContext context)
    {
        var ret = (ReturnStatementSyntax)context.Node;
        if (ret.Expression is null) return;

        // `return plain;` straight out of the Func<char[], T> callback —
        // the caller receives the array the library is about to zero.
        // A return from a nested lambda / local function stays inside
        // the Access window and is not flagged here.
        if (!TryResolveAccessParameter(ret.Expression, context, out var parameter, out var accessLambda)) return;
        if (parameter!.Type is not IArrayTypeSymbol) return;
        if (!IsSameNode(GetEnclosingFunction(ret), accessLambda)) return;

        context.ReportDiagnostic(Diagnostic.Create(
            CapturedArrayRule, ret.GetLocation(), parameter.Name, "its return value"));
    }

    private static void AnalyzeLambda(SyntaxNodeAnalysisContext context)
    {
        var lambda = (LambdaExpressionSyntax)context.Node;

        // Expression-bodied form of the same escape: `ps.Access(p => p)`.
        if (lambda.ExpressionBody is null) return;
        if (!TryResolveAccessParameter(lambda.ExpressionBody, context, out var parameter, out var accessLambda)) return;
        if (!IsSameNode(accessLambda, lambda)) return;
        if (parameter!.Type is not IArrayTypeSymbol) return;

        context.ReportDiagnostic(Diagnostic.Create(
            CapturedArrayRule, lambda.ExpressionBody.GetLocation(), parameter.Name, "its return value"));
    }

    /// <summary>
    /// Returns the first argument of <paramref name="arguments"/> that
    /// resolves (span-aware) to the Access plaintext parameter.
    /// </summary>
    private static bool TryFindPlaintextArgument(
        ArgumentListSyntax arguments,
        SyntaxNodeAnalysisContext context,
        out string parameterName)
    {
        foreach (var arg in arguments.Arguments)
        {
            if (TryGetPlaintextParameterName(arg.Expression, context, out parameterName))
            {
                return true;
            }
        }
        parameterName = string.Empty;
        return false;
    }

    /// <summary>
    /// Name-only convenience over <see cref="TryResolveAccessParameter"/>.
    /// </summary>
    private static bool TryGetAccessParameterName(
        ExpressionSyntax expression,
        SyntaxNodeAnalysisContext context,
        out string parameterName)
    {
        if (TryResolveAccessParameter(expression, context, out var parameter, out _))
        {
            parameterName = parameter!.Name;
            return true;
        }
        parameterName = string.Empty;
        return false;
    }

    /// <summary>
    /// Walks up the syntax tree from <paramref name="expression"/> looking
    /// for an enclosing scope (lambda or local function) that declares
    /// <paramref name="expression"/>'s parameter symbol, then keeps
    /// walking outward to find a lambda passed to
    /// <c>ProtectedString.Access(...)</c>. Returns the parameter symbol
    /// and the Access lambda on a hit; otherwise <see langword="false"/>.
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
    private static bool TryResolveAccessParameter(
        ExpressionSyntax expression,
        SyntaxNodeAnalysisContext context,
        out IParameterSymbol? parameter,
        out LambdaExpressionSyntax? accessLambda)
    {
        parameter = null;
        accessLambda = null;

        // Strip parentheses: `(plain)` should bind the same as `plain`.
        expression = StripParentheses(expression);

        if (expression is not IdentifierNameSyntax identifier) return false;

        var symbolInfo = context.SemanticModel.GetSymbolInfo(identifier, context.CancellationToken);
        if (symbolInfo.Symbol is not IParameterSymbol candidateParameter) return false;

        // Walk up to the scope that declares the parameter — either a
        // lambda or a local function. Anything else (regular method, ctor)
        // falls outside our analyzer's scope and we bail.
        SyntaxNode? declaringScope = identifier.Parent;
        while (declaringScope is not null)
        {
            if (declaringScope is LambdaExpressionSyntax lambda &&
                LambdaDeclaresParameter(lambda, candidateParameter))
            {
                break;
            }
            if (declaringScope is LocalFunctionStatementSyntax localFn &&
                LocalFunctionDeclaresParameter(localFn, candidateParameter))
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
                parameter = candidateParameter;
                accessLambda = candidate;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Like <see cref="TryGetAccessParameterName"/>, but additionally sees
    /// through the small set of well-known "view over the same memory"
    /// wrappers — <c>plain.AsSpan(...)</c>, <c>plain.AsMemory(...)</c>,
    /// <c>span.Slice(...)</c>, <c>span[a..b]</c>, <c>memory.Span</c>,
    /// <c>MemoryMarshal.AsBytes(...)</c>, and
    /// <c>MemoryMarshal.Cast&lt;TFrom, TTo&gt;(...)</c> — so that e.g.
    /// <c>Encoding.UTF8.GetString(MemoryMarshal.AsBytes(plain))</c> or
    /// <c>plain[..4].ToString()</c> still resolve to the Access plaintext
    /// parameter.
    /// </summary>
    /// <remarks>
    /// Anything else (user helpers, LINQ chains) is deliberately not
    /// chased: consistent with the analyzer's bias, we prefer a false
    /// negative on exotic dataflow over flagging a legitimate sink. Each
    /// wrapper is verified by symbol (containing type
    /// <c>System.MemoryExtensions</c>, <c>System.Span&lt;T&gt;</c> &amp;
    /// co., or <c>System.Runtime.InteropServices.MemoryMarshal</c>) so
    /// user methods that merely share the name cannot trigger.
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

            expression = StripParentheses(expression);

            switch (expression)
            {
                case ElementAccessExpressionSyntax element when IsRangeIndex(element):
                    // `plain[a..b]` — a re-slice on a span, a sub-array
                    // copy on an array; either way the bytes are the
                    // plaintext's.
                    expression = element.Expression;
                    continue;

                case MemberAccessExpressionSyntax { Name.Identifier.ValueText: "Span" } spanProperty
                    when context.SemanticModel.GetSymbolInfo(spanProperty, context.CancellationToken).Symbol
                             is IPropertySymbol spanProp &&
                         IsSpanOrMemoryType(spanProp.ContainingType):
                    // `memory.Span` — a span over the memory's buffer.
                    expression = spanProperty.Expression;
                    continue;

                case InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax member } invocation:
                    switch (member.Name.Identifier.ValueText)
                    {
                        case "AsSpan":
                        case "AsMemory":
                            // Reduced extension form: `plain.AsSpan(...)` —
                            // the wrapped expression is the receiver.
                            if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol
                                    is not IMethodSymbol asSpan ||
                                asSpan.ContainingType?.ToDisplayString() != "System.MemoryExtensions")
                            {
                                return false;
                            }
                            expression = member.Expression;
                            continue;

                        case "Slice":
                            // `span.Slice(...)` — same buffer, narrower window.
                            if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol
                                    is not IMethodSymbol slice ||
                                !IsSpanOrMemoryType(slice.ContainingType))
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

                default:
                    return false;
            }
        }
    }

    private static ExpressionSyntax StripParentheses(ExpressionSyntax expression)
    {
        while (expression is ParenthesizedExpressionSyntax paren)
        {
            expression = paren.Expression;
        }
        return expression;
    }

    private static bool IsRangeIndex(ElementAccessExpressionSyntax element) =>
        element.ArgumentList.Arguments.Count == 1 &&
        element.ArgumentList.Arguments[0].Expression is RangeExpressionSyntax;

    private static bool IsSpanOrMemoryType(INamedTypeSymbol? type)
    {
        if (type is null) return false;
        return type.OriginalDefinition.ToDisplayString() is
            "System.Span<T>" or
            "System.ReadOnlySpan<T>" or
            "System.Memory<T>" or
            "System.ReadOnlyMemory<T>";
    }

    private static bool ImplementsIEnumerable(INamedTypeSymbol type)
    {
        if (type.SpecialType == SpecialType.System_Collections_IEnumerable) return true;
        foreach (var iface in type.AllInterfaces)
        {
            if (iface.SpecialType == SpecialType.System_Collections_IEnumerable) return true;
        }
        return false;
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
        // Walk up through wrappers that don't change which argument the
        // lambda is: `ps.Access((ReadOnlySpanAction<char>)(p => ...))`
        // or `ps.Access((p => ...))`.
        SyntaxNode? node = lambda.Parent;
        while (node is ParenthesizedExpressionSyntax or CastExpressionSyntax)
        {
            node = node.Parent;
        }

        if (node is not ArgumentSyntax argument) return false;
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

    private static bool IsSameNode(SyntaxNode? a, SyntaxNode? b) =>
        a is not null && b is not null &&
        a.SyntaxTree == b.SyntaxTree &&
        a.Span == b.Span &&
        a.RawKind == b.RawKind;

    /// <summary>
    /// The innermost function-like node (lambda, anonymous method or
    /// local function) containing <paramref name="node"/>, or
    /// <see langword="null"/> when it sits directly in a member body.
    /// </summary>
    private static SyntaxNode? GetEnclosingFunction(SyntaxNode node)
    {
        for (SyntaxNode? cursor = node.Parent; cursor is not null; cursor = cursor.Parent)
        {
            switch (cursor)
            {
                case AnonymousFunctionExpressionSyntax:
                case LocalFunctionStatementSyntax:
                    return cursor;
                case MemberDeclarationSyntax:
                    return null;
            }
        }
        return null;
    }

    /// <summary>
    /// <see langword="true"/> when <paramref name="local"/> is declared
    /// outside <paramref name="accessLambda"/> — i.e. it is a captured
    /// local that outlives the Access callback. A local declared inside
    /// the Access lambda (even when the assignment happens in a nested
    /// lambda) dies with the callback's frame and is not an escape.
    /// </summary>
    private static bool IsDeclaredOutside(
        ILocalSymbol local,
        LambdaExpressionSyntax accessLambda,
        System.Threading.CancellationToken cancellationToken)
    {
        var declaringRef = local.DeclaringSyntaxReferences;
        if (declaringRef.Length == 0) return false;
        var declarationNode = declaringRef[0].GetSyntax(cancellationToken);

        return declarationNode.SyntaxTree != accessLambda.SyntaxTree ||
               !accessLambda.Span.Contains(declarationNode.Span);
    }
}
