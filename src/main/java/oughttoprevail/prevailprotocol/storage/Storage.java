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
package oughttoprevail.prevailprotocol.storage;

import java.io.Flushable;
import java.util.List;
import java.util.Queue;

import oughttoprevail.prevailprotocol.storage.collection.FieldList;
import oughttoprevail.prevailprotocol.storage.collection.FieldQueue;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A {@link Storage} is responsible for creating fields and updating their storage value on {@link #flush()}.
 */
public interface Storage extends Flushable
{
	/**
	 * @param serDes to serialize and deserialize the {@link Field} with
	 * @param <T> type of object to store in the {@link Field}
	 * @return a single {@link Field} which can be serialized and deserialized using the specified serDes and the specified settings.
	 */
	<T> Field<T> getField(SerDes<T> serDes);
	
	/*
	NOTE: There is only one or no list/queue per storage and it's always at the end
	 */
	
	/**
	 * @param serDes to serialize and deserialize objects in the list
	 * @param <T> type of object to store in the {@link List}
	 * @return a {@link List} of a object with each object in the underlying list having the same behavior as a {@link Field}
	 */
	default <T> List<T> getFieldList(SerDes<T> serDes)
	{
		return new FieldList<>(this, serDes);
	}
	
	/**
	 * @param serDes to serialize and deserialize objects in the queue
	 * @param <T> type of object to store in the {@link Queue}
	 * @return a {@link Queue} of a object with each object in the underlying queue having the same behavior as a {@link Field}
	 */
	default <T> Queue<T> getFieldQueue(SerDes<T> serDes)
	{
		return new FieldQueue<>(this, serDes);
	}
	
	/**
	 * Flushes all changes into storage.
	 */
	void flush();
}