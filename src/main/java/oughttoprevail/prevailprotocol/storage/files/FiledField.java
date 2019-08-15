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
package oughttoprevail.prevailprotocol.storage.files;

import oughttoprevail.prevailprotocol.rw.ByteBufferOutput;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A file writable field.
 *
 * @param <T> type of field
 */
class FiledField<T> extends Field<T>
{
	/**
	 * The field serializer and deserializer
	 */
	private final SerDes<T> serDes;
	
	/**
	 * Constructs a new {@link FiledField} using the specified parameters.
	 *
	 * @param serDes to serialize and deserialize the value with
	 * @param initialValue to be the initial value, possibly the value read from storage
	 */
	FiledField(SerDes<T> serDes, T initialValue)
	{
		super(initialValue);
		this.serDes = serDes;
	}
	
	/**
	 * Writes the field to the specified out.
	 *
	 * @param out to write the field to
	 * @param settings to use
	 */
	void write(ByteBufferOutput out, Settings settings)
	{
		T value = get();
		if(value == null)
		{
			out.writeBoolean(false);
			return;
		}
		out.writeBoolean(true);
		serDes.serialize(value, out, settings);
	}
}