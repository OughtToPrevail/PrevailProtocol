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
package oughttoprevail.prevailprotocol.storage;

import java.util.List;

import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;

/**
 * Storage for messages which are represented as a {@code byte[]}.
 */
public class MailboxStorage
{
	/**
	 * Messages storage name
	 */
	private static final String MESSAGES_STORAGE = "Messages";
	
	/**
	 * Storage to store messages in
	 */
	private final Storage storage;
	/**
	 * List of {@code byte[]} and each {@code byte[]} will be a message
	 */
	private final List<byte[]> messages;
	
	/**
	 * Constructs a new {@link MailboxStorage} with the specified userDirectory.
	 *
	 * @param userDirectory in which the new storage should be created
	 */
	public MailboxStorage(Directory userDirectory)
	{
		this.storage = userDirectory.storage(MESSAGES_STORAGE);
		this.messages = storage.getFieldList(JavaSerDes.BYTE_ARRAY_SER_DES);
	}
	
	/**
	 * Adds the specified message to the messages list.
	 *
	 * @param message to add to the messages list
	 */
	public void addMessage(byte[] message)
	{
		messages.add(message);
		storage.flush();
	}
	
	/**
	 * Removes the specified message.
	 *
	 * @param message to remove
	 */
	public void removeMessage(byte[] message)
	{
		messages.remove(message);
	}
	
	/**
	 * @return a list of messages (each {@code byte[]} in the list is a message)
	 */
	public List<byte[]> getMessages()
	{
		return messages;
	}
}