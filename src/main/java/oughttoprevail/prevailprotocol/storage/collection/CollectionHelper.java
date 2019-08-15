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
package oughttoprevail.prevailprotocol.storage.collection;

import java.util.Collection;
import java.util.Iterator;

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.CounterField;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.JavaSerDes;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A stored {@link Collection} helper.
 *
 * @param <E> type of object to store
 */
class CollectionHelper<E>
{
	/**
	 * The storage who created this
	 */
	private final Storage storage;
	/**
	 * The serializer and deserializer of {@link E}
	 */
	private final SerDes<E> serDes;
	/**
	 * Size of the list
	 */
	private final CounterField size;
	
	/**
	 * Constructs a new {@link CollectionHelper} using the specified parameters.
	 *
	 * @param storage to store the fields in
	 * @param serDes to serialize and deserialize {@link E} with
	 * @param backingCollection the {@link Collection} backing the {@link E} {@link Collection}
	 */
	CollectionHelper(Storage storage, SerDes<E> serDes, Collection<Field<E>> backingCollection)
	{
		this.serDes = serDes;
		this.storage = storage;
		Field<Integer> sizeField = storage.getField(JavaSerDes.INTEGER_SER_DES);
		this.size = new CounterField(sizeField);
		//load all fields
		int size = this.size.get();
		for(int i = 0; i < size; i++)
		{
			Field<E> field = createField();
			backingCollection.add(field);
		}
	}
	
	/**
	 * Creates a {@link Field} then sets it's value to the specified value and increments the size.
	 *
	 * @return a new {@link Field} with the specified value
	 */
	Field<E> getField(E value)
	{
		Field<E> field = createField();
		field.set(value);
		size.increment();
		return field;
	}
	
	/**
	 * @return a new {@link Field}
	 */
	private Field<E> createField()
	{
		return storage.getField(serDes);
	}
	
	/**
	 * Decrements the size and iterates through the fields setting each value to the next value in the collection, and the last field value to
	 * {@code null}.
	 *
	 * @param iterator to iterate with
	 */
	void removed(Iterator<Field<E>> iterator)
	{
		Field<E> current = iterator.next();
		while(iterator.hasNext())
		{
			Field<E> next = iterator.next();
			current.set(next.get());
			current = next;
		}
		current.set(null);
		iterator.remove();
		decrementSize();
	}
	
	/**
	 * Decrements the stored size
	 */
	void decrementSize()
	{
		size.decrement();
	}
}