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

import oughttoprevail.prevailprotocol.util.Consumer;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link Consumer} based reader.
 */
public interface ConsumerReader
{
	/**
	 * Reads the specified bytes amount of bytes then accepts the specified consumer with the read bytes as a {@code byte[]}.
	 *
	 * @param consumer to accept when the read operation has finished
	 * @param bytes amount of bytes to read
	 */
	void readBytes(Consumer<byte[]> consumer, int bytes);
	
	/**
	 * Reads a single {@link Boolean} then accepts the specified consumer with it.
	 *
	 * @param consumer to accept with the read {@link Boolean}
	 */
	default void readBoolean(Consumer<Boolean> consumer)
	{
		readBytes(aBoolean -> consumer.accept(Util.booleanFromBytes(aBoolean)), Util.BYTE_BYTES);
	}
	
	/**
	 * Reads a single {@link Integer} then accepts the specified consumer with it.
	 *
	 * @param consumer to accept with the read {@link Integer}
	 */
	default void readInt(Consumer<Integer> consumer)
	{
		readBytes(intBytes -> consumer.accept(Util.bytesToInt(intBytes)), Util.INT_BYTES);
	}
}