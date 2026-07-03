namespace TopSecret;

/// <summary>
/// A callback that receives a <see cref="ReadOnlySpan{T}"/> by value. Used by
/// <see cref="ProtectedString.Access(ReadOnlySpanAction{char})"/> to hand the
/// plaintext to the caller in a form that the C# compiler refuses to let
/// escape — <see cref="ReadOnlySpan{T}"/> is a <c>ref struct</c>, so it
/// cannot be captured by a closure, stored in a field, returned, or crossed
/// by an <c>await</c>. This closes the most common accidental-leak patterns
/// of the older <see cref="System.Action{T}"/>-of-<c>char[]</c> shape.
/// </summary>
/// <typeparam name="T">Element type of the span.</typeparam>
/// <param name="span">The span to operate on. Valid only for the duration of the call.</param>
public delegate void ReadOnlySpanAction<T>(ReadOnlySpan<T> span);

/// <summary>
/// Like <see cref="ReadOnlySpanAction{T}"/>, but returns
/// <typeparamref name="TResult"/> to the caller. Used by
/// <see cref="ProtectedString.Access{T}(ReadOnlySpanFunc{char, T})"/> when
/// the caller needs to derive a value from the plaintext (e.g. its length,
/// a parse result, an HMAC) without copying the plaintext into a
/// heap-allocated <c>char[]</c>.
/// </summary>
/// <typeparam name="T">Element type of the span.</typeparam>
/// <typeparam name="TResult">Type of the value returned by the callback.</typeparam>
/// <param name="span">The span to operate on. Valid only for the duration of the call.</param>
public delegate TResult ReadOnlySpanFunc<T, out TResult>(ReadOnlySpan<T> span);
