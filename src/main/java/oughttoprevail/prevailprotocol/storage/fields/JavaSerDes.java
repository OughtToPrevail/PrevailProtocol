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

import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * An interface storing the {@link SerDes} which are for objects from Java.
 */
public interface JavaSerDes
{
	/**
	 * A {@link SerDes} which serializes and deserializes {@code byte[]}
	 */
	SerDes<byte[]> BYTE_ARRAY_SER_DES = new SerDes<byte[]>()
	{
		@Override
		public void serialize(byte[] bytes, FieldOutputStream out, Settings settings)
		{
			out.writeBytes(bytes);
		}
		
		@Override
		public byte[] deserialize(FieldInputStream in, Settings settings)
		{
			return in.readBytes();
		}
	};
	/**
	 * A {@link SerDes} which serializes and deserializes {@link Integer}
	 */
	SerDes<Integer> INTEGER_SER_DES = new SerDes<Integer>()
	{
		@Override
		public void serialize(Integer integer, FieldOutputStream out, Settings settings)
		{
			out.writeInt(integer);
		}
		
		@Override
		public Integer deserialize(FieldInputStream in, Settings settings)
		{
			return in.readInt();
		}
	};
	/**
	 * A {@link SerDes} which serializes and deserializes {@link Long}
	 */
	SerDes<Long> LONG_SER_DES = new SerDes<Long>()
	{
		@Override
		public void serialize(Long aLong, FieldOutputStream out, Settings settings)
		{
			out.writeLong(aLong);
		}
		
		@Override
		public Long deserialize(FieldInputStream in, Settings settings)
		{
			return in.readLong();
		}
	};
}