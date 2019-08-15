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

import oughttoprevail.prevailprotocol.exception.NotEnoughBytesException;
import oughttoprevail.prevailprotocol.rw.ByteBufferInput;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.files.FiledStorage;
import oughttoprevail.prevailprotocol.util.Consumer;

/**
 * A {@link FiledStorage} input.
 */
public class StorageFileInput extends ByteBufferInput
{
	/**
	 * The readable file channel
	 */
	private final FileChannel fileChannel;
	/**
	 * The {@link IOException} catcher
	 */
	private final Consumer<IOException> exceptionCatcher;
	
	/**
	 * Constructs a new {@link StorageFileInput}.
	 *
	 * @param fileChannel to read data from (must be a readable {@link FileChannel})
	 * @param exceptionCatcher to invoke when {@link IOException}s occur
	 * @param settings to use
	 */
	public StorageFileInput(FileChannel fileChannel, ByteBuffer readByteBuffer, Consumer<IOException> exceptionCatcher, Settings settings)
	{
		super(readByteBuffer, settings);
		//set the position to capacity so read() will know the buffer is empty
		readByteBuffer.limit(readByteBuffer.capacity());
		readByteBuffer.position(readByteBuffer.capacity());
		this.fileChannel = fileChannel;
		this.exceptionCatcher = exceptionCatcher;
	}
	
	/**
	 * Whether it has reached EOF (End of file)
	 */
	private boolean eof;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean hasNext()
	{
		if(eof)
		{
			return false;
		}
		return super.hasNext();
	}
	
	/**
	 * If the remaining bytes in the specified byteBuffer are less than the specified bytes more bytes are read from the channel, if there is still
	 * not enough then a {@link NotEnoughBytesException} is thrown
	 */
	@Override
	protected void read(ByteBuffer byteBuffer, int bytes)
	{
		int remaining = byteBuffer.remaining();
		if(remaining < bytes)
		{
			try
			{
				if(remaining == 0)
				{
					byteBuffer.clear();
				} else
				{
					byteBuffer.compact();
				}
				int read = fileChannel.read(byteBuffer);
				if(byteBuffer.flip().limit() >= bytes)
				{
					return;
				}
				eof = read == -1;
				throw new NotEnoughBytesException();
			} catch(IOException e)
			{
				exceptionCatcher.accept(e);
			}
		}
	}
}