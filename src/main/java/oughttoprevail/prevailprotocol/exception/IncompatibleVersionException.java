package oughttoprevail.prevailprotocol.exception;

/**
 * Thrown when a client has connected to a server with a different version.
 */
public class IncompatibleVersionException extends IllegalArgumentException
{
	/**
	 * Constructs a new {@link IncompatibleVersionException} and creates a message with the specified myVersion and specified incompatibleVersion.
	 *
	 * @param myVersion is the version which is incompatible with the specified incompatibleVersion
	 * @param incompatibleVersion the version of the server
	 */
	public IncompatibleVersionException(int myVersion, int incompatibleVersion)
	{
		super("Incompatible version (" + incompatibleVersion + "), must be at least " + myVersion + "!");
	}
}