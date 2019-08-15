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
package oughttoprevail.prevailprotocol.rw;

import java.nio.ByteBuffer;

import oughttoprevail.prevailprotocol.exception.NotEnoughBytesException;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link ByteBuffer} based implementation of {@link FieldInputStream}
 */
public abstract class ByteBufferInput implements FieldInputStream
{
	/**
	 * {@link ByteBuffer} to read input with
	 */
	private final ByteBuffer byteBuffer;
	/**
	 * Settings to use
	 */
	private final Settings settings;
	
	/**
	 * Constructs a new {@link ByteBufferInput} using the specified byteBuffer as input.
	 *
	 * @param byteBuffer to use as input
	 * @param settings to use
	 */
	protected ByteBufferInput(ByteBuffer byteBuffer, Settings settings)
	{
		this.byteBuffer = byteBuffer;
		this.settings = settings;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasNext()
	{
		try
		{
			return readBoolean();
		} catch(NotEnoughBytesException ignored)
		{
			return false;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean readBoolean()
	{
		byte b = readByte();
		return b == 1;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte readByte()
	{
		read(Util.BYTE_BYTES);
		return byteBuffer.get();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] readBytes()
	{
		int length = readInt();
		int position = 0;
		int capacity = byteBuffer.capacity();
		byte[] bytes = new byte[length];
		while(position < length)
		{
			int read = Math.min(capacity, length - position);
			read(read);
			byteBuffer.get(bytes, position, read);
			position += read;
		}
		return bytes;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public short readShort()
	{
		read(Util.SHORT_BYTES);
		return byteBuffer.getShort();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public int readInt()
	{
		read(Util.INT_BYTES);
		return byteBuffer.getInt();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public long readLong()
	{
		read(Util.LONG_BYTES);
		return byteBuffer.getLong();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public <T> T readObject(SerDes<T> serDes)
	{
		return serDes.deserialize(this, settings);
	}
	
	/**
	 * {@inheritDoc}
	 */
	private void read(int bytes)
	{
		read(byteBuffer, bytes);
	}
	
	/**
	 * Ensures the specified byteBuffer has the specified amount of bytes.
	 *
	 * @param byteBuffer to ensure has the specified amount of bytes
	 * @param bytes to ensure the specified byteBuffer has
	 */
	protected abstract void read(ByteBuffer byteBuffer, int bytes);
}