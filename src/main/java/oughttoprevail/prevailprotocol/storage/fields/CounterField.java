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

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.util.Util;

/**
 * A counter wrapper for {@link Field}.
 */
public class CounterField
{
	/**
	 * A backing {@link Field} which controls the actual storage
	 */
	private final Field<Integer> backingField;
	/**
	 * A primitive value to increase performance (instead of unboxing a primitive value will be used here)
	 */
	private int value;
	
	/**
	 * Constructs a new {@link CounterField} to wrap around the specified backingField.
	 *
	 * @param backingField to store the counter in
	 */
	public CounterField(Field<Integer> backingField)
	{
		this.backingField = backingField;
		Integer value = backingField.get();
		if(value != null)
		{
			this.value = value;
		}
	}
	
	/**
	 * Constructs a new {@link CounterField} which creates a {@link Field} using the specified parameters then invokes {@link #CounterField(Field)}
	 *
	 * @param storage to create field with
	 */
	public CounterField(Storage storage)
	{
		this(storage.getField(JavaSerDes.INTEGER_SER_DES));
	}
	
	/**
	 * Increment the counter.
	 */
	public void increment()
	{
		backingField.set(++value);
	}
	
	/**
	 * Decrement the counter.
	 */
	public void decrement()
	{
		backingField.set(--value);
	}
	
	/**
	 * A zero boxed {@link Integer} value.
	 */
	private static final Integer ZERO = 0;
	
	/**
	 * Resets the counter value to {@code 0}.
	 */
	public void reset()
	{
		backingField.set(ZERO);
		value = 0;
	}
	
	/**
	 * @return the current value of the counter
	 */
	public int get()
	{
		return value;
	}
	
	/**
	 * @return the current value of the counter as bytes
	 */
	public byte[] getBytes()
	{
		return Util.intToBytes(get());
	}
}