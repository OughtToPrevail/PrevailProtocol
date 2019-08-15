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

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link ByteBuffer} based implementation of {@link FieldOutputStream}
 */
public abstract class ByteBufferOutput implements FieldOutputStream
{
	/**
	 * Settings to use
	 */
	private final Settings settings;
	/**
	 * {@link ByteBuffer} to write with
	 */
	private ByteBuffer writeByteBuffer;
	
	/**
	 * Constructs a new {@link ByteBufferOutput}.
	 *
	 * @param writeByteBuffer to write with
	 * @param settings to use
	 */
	protected ByteBufferOutput(ByteBuffer writeByteBuffer, Settings settings)
	{
		this.writeByteBuffer = writeByteBuffer;
		this.settings = settings;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeByte(int b)
	{
		write(Util.BYTE_BYTES);
		writeByteBuffer.put((byte) b);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeBytes(byte[] b)
	{
		int length = b.length;
		writeInt(length);
		int position = 0;
		int capacity = writeByteBuffer.capacity();
		while(position < length)
		{
			int write = Math.min(/*remaining*/length - position, capacity);
			write(write);
			writeByteBuffer.put(b, position, write);
			position += write;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeBoolean(boolean v)
	{
		writeByte(v ? 1 : 0);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeShort(short s)
	{
		write(Util.SHORT_BYTES);
		writeByteBuffer.putShort(s);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeInt(int v)
	{
		write(Util.INT_BYTES);
		writeByteBuffer.putInt(v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeLong(long v)
	{
		write(Util.LONG_BYTES);
		writeByteBuffer.putLong(v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public <T> void writeObject(T t, SerDes<T> serDes)
	{
		serDes.serialize(t, this, settings);
	}
	
	/**
	 * Ensures the byteBuffer has enough space remaining to write the specified amount of bytes.
	 *
	 * @param bytes to ensure the byteBuffer has enough space for
	 */
	protected abstract void write(int bytes);
	
	/**
	 * @return the current byteBuffer
	 */
	protected ByteBuffer getWriteByteBuffer()
	{
		return writeByteBuffer;
	}
}