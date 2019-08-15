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
 * A field serializer and deserializer.
 *
 * @param <T> type of object to serialize and deserialize
 */
public interface SerDes<T>
{
	/**
	 * Serializes the specified t into the specified out using the specified settings.
	 *
	 * @param t to serialize (never null)
	 * @param out to serialize into (put the serialized data into)
	 * @param settings to use
	 */
	void serialize(T t, FieldOutputStream out, Settings settings);
	
	/**
	 * Deserializes {@link T} from the specified in using the specified settings.
	 *
	 * @param in to deserialize from
	 * @param settings to use
	 * @return the deserialized {@link T} (never null)
	 */
	T deserialize(FieldInputStream in, Settings settings);
}