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

import oughttoprevail.prevailprotocol.util.Util;

/**
 * A blocking reader for {@code byte[]}, {@code boolean} and {@code int}.
 */
public interface Reader
{
	/**
	 * @param bytes amount of bytes to read
	 * @return read bytes
	 */
	byte[] readBytes(int bytes);
	
	/**
	 * @return a single read boolean
	 */
	default boolean readBoolean()
	{
		return Util.booleanFromBytes(readBytes(Util.BYTE_BYTES));
	}
	
	/**
	 * @return a single read int
	 */
	default int readInt()
	{
		return Util.bytesToInt(readBytes(Util.INT_BYTES));
	}
}