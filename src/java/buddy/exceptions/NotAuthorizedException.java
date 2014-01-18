package buddy.exceptions;

public class NotAuthorizedException extends java.lang.Exception {
    private final Object metadata;
    public NotAuthorizedException(Object metadata) {
        this.metadata = metadata;
    }

    public Object getMetadata() {
        return metadata;
    }
}
