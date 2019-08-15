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

import java.nio.ByteBuffer;

/**
 * A {@code byte[]} reader.
 */
public class ByteArrayReader implements Reader
{
	/**
	 * ByteBuffer to read with
	 */
	private final ByteBuffer byteBuffer;
	
	/**
	 * Constructs a new {@link ByteArrayReader}.
	 *
	 * @param message to read
	 */
	public ByteArrayReader(byte[] message)
	{
		this.byteBuffer = ByteBuffer.wrap(message);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] readBytes(int bytes)
	{
		byte[] result = new byte[bytes];
		byteBuffer.get(result);
		return result;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean readBoolean()
	{
		return byteBuffer.get() == 1;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public int readInt()
	{
		return byteBuffer.getInt();
	}
}