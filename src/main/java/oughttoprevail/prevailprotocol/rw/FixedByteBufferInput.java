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

/**
 * A {@link ByteBufferInput} implementation which will throw a {@link IllegalArgumentException} when the specified byteBuffer doesn't have enough
 * bytes to complete a read operation.
 * Note: this implementation only supports heap {@link ByteBuffer}.
 */
public class FixedByteBufferInput extends ByteBufferInput
{
	/**
	 * Equals to {@link ByteBufferInput#ByteBufferInput(ByteBuffer, oughttoprevail.prevailprotocol.settings.Settings)}.
	 */
	public FixedByteBufferInput(ByteBuffer byteBuffer, Settings settings)
	{
		super(byteBuffer, settings);
	}
	
	/**
	 * @throws IllegalArgumentException if the specified byteBuffer remaining bytes are less then the specified bytes.
	 */
	@Override
	protected void read(ByteBuffer byteBuffer, int bytes)
	{
		if(byteBuffer.remaining() < bytes)
		{
			throw new IllegalArgumentException("Given ByteBuffer too short!");
		}
	}
}