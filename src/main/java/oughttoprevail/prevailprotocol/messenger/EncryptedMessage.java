/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.messenger;

import oughttoprevail.prevailprotocol.uid.UserDeviceUID;

/**
 * A {@link EncryptedMessage} keeps hold of the encrypted {@code byte[]} message and it's user device destination.
 */
public class EncryptedMessage
{
	/**
	 * Destination which the message was encrypted for
	 */
	private final UserDeviceUID destination;
	/**
	 * The result of the encryption
	 */
	private final byte[] encryptedMessage;
	
	/**
	 * Constructs a new {@link EncryptedMessage}.
	 *
	 * @param destination which the message was encrypted for
	 * @param encryptedMessage result of the encryption
	 */
	public EncryptedMessage(UserDeviceUID destination, byte[] encryptedMessage)
	{
		this.destination = destination;
		this.encryptedMessage = encryptedMessage;
	}
	
	/**
	 * @return destination of the message (where the message was encrypted for)
	 */
	public UserDeviceUID getDestination()
	{
		return destination;
	}
	
	/**
	 * @return the encrypted message (result of the encryption)
	 */
	public byte[] getEncryptedMessage()
	{
		return encryptedMessage;
	}
}