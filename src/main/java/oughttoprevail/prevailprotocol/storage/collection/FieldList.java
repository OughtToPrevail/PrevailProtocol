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

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A {@link List} of type E backed by a {@link Field} for each element in the list.
 *
 * @param <E> type of object to store in the list
 */
public class FieldList<E> extends AbstractList<E>
{
	private final CollectionHelper<E> collectionHelper;
	/**
	 * The backing {@link Field} {@link ArrayList}
	 */
	private final List<Field<E>> backingList = new ArrayList<>();
	
	/**
	 * Constructs a new {@link FieldList} for the specified storage.
	 *
	 * @param storage who is creating this
	 * @param serDes to serialize and deserialize elements of this collection with
	 */
	public FieldList(Storage storage, SerDes<E> serDes)
	{
		collectionHelper = new CollectionHelper<>(storage, serDes, backingList);
	}
	
	/**
	 * @return the size of the backing list
	 */
	@Override
	public int size()
	{
		return backingList.size();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean add(E e)
	{
		Field<E> field = collectionHelper.getField(e);
		backingList.add(field);
		return true;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public E get(int index)
	{
		return backingList.get(index).get();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public E remove(int index)
	{
		Field<E> field = backingList.get(index);
		E previousValue = field.get();
		collectionHelper.removed(backingList.subList(index, size()).iterator());
		return previousValue;
	}
}