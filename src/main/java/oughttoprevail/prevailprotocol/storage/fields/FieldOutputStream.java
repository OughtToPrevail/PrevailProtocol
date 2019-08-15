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
package oughttoprevail.prevailprotocol.storage.fields;

/**
 * A output stream for fields to use when serializing.
 */
public interface FieldOutputStream
{
	/**
	 * Writes the specified byte.
	 *
	 * @param b to write
	 */
	void writeByte(int b);
	
	/**
	 * Writes the specified bytes.
	 *
	 * @param bytes to write
	 */
	void writeBytes(byte[] bytes);
	
	/**
	 * Writes the specified b.
	 *
	 * @param b to write
	 */
	void writeBoolean(boolean b);
	
	/**
	 * Writes the specified s.
	 *
	 * @param s to write
	 */
	void writeShort(short s);
	
	/**
	 * Writes the specified i.
	 *
	 * @param i to write
	 */
	void writeInt(int i);
	
	/**
	 * Writes the specified l.
	 *
	 * @param l to write
	 */
	void writeLong(long l);
	
	/**
	 * Serializes the specified t into this output stream.
	 *
	 * @param t to write
	 * @param serDes to serialize the specified t with
	 * @param <T> type of object
	 */
	<T> void writeObject(T t, SerDes<T> serDes);
}