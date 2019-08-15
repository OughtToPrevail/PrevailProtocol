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

/**
 * A {@code synchronized} version of {@link MailboxStorage}.
 */
public class SynchronizedMailboxStorage extends MailboxStorage
{
	public SynchronizedMailboxStorage(Directory userDirectory)
	{
		super(userDirectory);
	}
	
	@Override
	public synchronized void addMessage(byte[] message)
	{
		super.addMessage(message);
	}
	
	@Override
	public synchronized void removeMessage(byte[] message)
	{
		super.removeMessage(message);
	}
	
	@Override
	public synchronized List<byte[]> getMessages()
	{
		return super.getMessages();
	}
}