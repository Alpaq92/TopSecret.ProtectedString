using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace TopSecret.Analyzers;

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
            if (methodSymbol.Name == "GetString" &&
                TryFindPlaintextArgument(invocation.ArgumentList, context, out var decodedArg))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    CopyToStringRule, invocation.GetLocation(), decodedArg));
                return;
            }

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

        if (containingType.ToDisplayString() == "System.Convert" &&
            methodSymbol.ReturnType.SpecialType == SpecialType.System_String &&
            TryFindPlaintextArgument(invocation.ArgumentList, context, out var convertedArg))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                CopyToStringRule, invocation.GetLocation(), convertedArg));
            return;
        }

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

        if (parameter!.Type is not IArrayTypeSymbol) return;

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
        for (INamedTypeSymbol? cursor = type; cursor is not null; cursor = cursor.BaseType)
        {
            if (cursor.ToDisplayString() == "System.Text.Encoding") return true;
        }
        return false;
    }

    private static bool LambdaDeclaresParameter(LambdaExpressionSyntax lambda, IParameterSymbol parameter)
    {
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
