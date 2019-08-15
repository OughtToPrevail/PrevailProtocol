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
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link ByteBufferOutput} implementation which transforms the written values into a {@code byte[]}.
 * Note: this implementation only supports heap {@link ByteBuffer}.
 */
public class ByteArrayOutput extends ByteBufferOutput
{
	/**
	 * Current result of this output, encase the output is too large or a byte array is requested this result should be updated
	 */
	private byte[] result;
	
	/**
	 * Equals to {@link ByteBufferOutput#ByteBufferOutput(ByteBuffer, Settings)}.
	 */
	public ByteArrayOutput(ByteBuffer writeByteBuffer, Settings settings)
	{
		super(writeByteBuffer, settings);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void write(int bytes)
	{
		ByteBuffer byteBuffer = getWriteByteBuffer();
		if(byteBuffer.remaining() < bytes)
		{
			//if we ran out of space update the result
			updateResult();
		}
	}
	
	/**
	 * @return the written values represented as a byte array
	 */
	public byte[] toByteArray()
	{
		updateResult();
		return result;
	}
	
	/**
	 * Updates the {@link #result} to contain the {@code byte[]} specified in the {@link #getWriteByteBuffer()}
	 */
	private void updateResult()
	{
		ByteBuffer byteBuffer = getWriteByteBuffer();
		try
		{
			result = Util.range(byteBuffer.array(), 0, byteBuffer.position());
		} finally
		{
			byteBuffer.clear();
		}
	}
}