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

import java.util.AbstractQueue;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Queue;

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A {@link Queue} of type E backed by a {@link Field} for each element in the list.
 *
 * @param <E> type of object to store in the list
 */
public class FieldQueue<E> extends AbstractQueue<E>
{
	/**
	 * Collection helper to help manage storage of this queue
	 */
	private final CollectionHelper<E> collectionHelper;
	
	/**
	 * A backing field queue
	 */
	private final Deque<Field<E>> backingQueue = new ArrayDeque<>();
	
	/**
	 * Constructs a new {@link FieldQueue}.
	 *
	 * @param storage who created this queue
	 * @param serDes to serialize and deserialize elements of this collection with
	 */
	public FieldQueue(Storage storage, SerDes<E> serDes)
	{
		collectionHelper = new CollectionHelper<>(storage, serDes, backingQueue);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Iterator<E> iterator()
	{
		Iterator<Field<E>> backingIterator = backingQueue.descendingIterator();
		return new Iterator<E>()
		{
			private Field<E> current;
			
			@Override
			public boolean hasNext()
			{
				return backingIterator.hasNext();
			}
			
			@Override
			public E next()
			{
				current = backingIterator.next();
				return current.get();
			}
			
			@Override
			public void remove()
			{
				collectionHelper.removed(backingIterator);
				current = null;
			}
		};
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public int size()
	{
		return backingQueue.size();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean offer(E e)
	{
		Field<E> field = collectionHelper.getField(e);
		backingQueue.offerFirst(field);
		return true;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public E poll()
	{
		Field<E> field = backingQueue.pollLast();
		if(field == null)
		{
			return null;
		}
		E element = field.get();
		field.set(null);
		collectionHelper.decrementSize();
		return element;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public E peek()
	{
		Field<E> field = backingQueue.peekLast();
		return field == null ? null : field.get();
	}
}