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
package oughttoprevail.prevailprotocol.storage.files.rw;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import oughttoprevail.prevailprotocol.rw.ByteBufferOutput;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.files.FiledStorage;
import oughttoprevail.prevailprotocol.util.Consumer;

/**
 * A {@link FiledStorage} output
 */
public class StorageFileOutput extends ByteBufferOutput
{
	/**
	 * The writable file channel
	 */
	private final FileChannel fileChannel;
	/**
	 * The {@link IOException} catcher
	 */
	private final Consumer<IOException> exceptionCatcher;
	
	/**
	 * Constructs a new {@link StorageFileInput}.
	 *
	 * @param fileChannel to write data to
	 * @param writeByteBuffer to write with
	 * @param exceptionCatcher to invoke when {@link IOException}s occur
	 * @param settings to use
	 */
	public StorageFileOutput(FileChannel fileChannel, ByteBuffer writeByteBuffer, Consumer<IOException> exceptionCatcher, Settings settings)
	{
		super(writeByteBuffer, settings);
		this.fileChannel = fileChannel;
		this.exceptionCatcher = exceptionCatcher;
	}
	
	/**
	 * Flushes the byteBuffer if there isn't enough space for the specified amount of bytes.
	 */
	@Override
	protected void write(int bytes)
	{
		ByteBuffer byteBuffer = getWriteByteBuffer();
		if(byteBuffer.remaining() < bytes)
		{
			flush();
		}
	}
	
	/**
	 * Flushes only if there are remaining bytes in the byteBuffer.
	 */
	public void flushIfRemaining()
	{
		if(getWriteByteBuffer().position() > 0)
		{
			flush();
		}
		getWriteByteBuffer().clear();
	}
	
	/**
	 * Flushes the {@link ByteBuffer} into the fileChannel.
	 */
	private void flush()
	{
		ByteBuffer byteBuffer = getWriteByteBuffer();
		byteBuffer.flip();
		try
		{
			while(byteBuffer.hasRemaining())
			{
				fileChannel.write(byteBuffer);
			}
		} catch(IOException e)
		{
			exceptionCatcher.accept(e);
		}
		byteBuffer.clear();
	}
}