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
 * A input stream for fields to use when deseralizing
 */
public interface FieldInputStream
{
	/**
	 * @return whether there is another field
	 */
	boolean hasNext();
	
	/**
	 * @return a read boolean
	 */
	boolean readBoolean();
	
	/**
	 * @return a read byte
	 */
	byte readByte();
	
	/**
	 * @return read bytes
	 */
	byte[] readBytes();
	
	/**
	 * @return read short
	 */
	short readShort();
	
	/**
	 * @return read int
	 */
	int readInt();
	
	/**
	 * @return read long
	 */
	long readLong();
	
	/**
	 * @param serDes to deserialize object with
	 * @param <T> type of object
	 * @return deserialized read object
	 */
	<T> T readObject(SerDes<T> serDes);
}