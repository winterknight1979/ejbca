package org.cesecore;

public class CesecoreRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1L;
     /** Constructs a new runtime exception with the specified cause and a
     * detail message of {@code (cause==null ? null : cause.toString())}
     * (which typically contains the class and detail message of
     * {@code cause}).  This constructor is useful for runtime exceptions
     * that are little more than wrappers for other throwables.
     *
     * @param  cause the cause (which is saved for later retrieval by the
     *         {@link #getCause()} method).  (A {@code null} value is
     *         permitted, and indicates that the cause is nonexistent or
     *         unknown.)
     */
    public CesecoreRuntimeException(final Throwable cause) {
        super(cause);
    }

    /**
     * @param msg msg
     * @param cause cause
     */
    public CesecoreRuntimeException(final String msg, final Throwable cause) {
        super(msg, cause);
    }

}
