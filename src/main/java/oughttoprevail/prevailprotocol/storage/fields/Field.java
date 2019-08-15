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
 * A {@link Field} is a class which controls a single object.
 * This class is very useful to always have an object even if the value is {@code null} and allows for classes to detect changes (by overriding set)
 *
 * @param <T> type of object for this field to control
 */
public class Field<T>
{
	/**
	 * The value of the {@link Field}
	 */
	private T value;
	
	/**
	 * Constructs a new {@link Field} with the specified initialValue to be set as the value.
	 *
	 * @param initialValue to be set as the value
	 */
	public Field(T initialValue)
	{
		this.value = initialValue;
	}
	
	/**
	 * Sets the specified value as the current value.
	 *
	 * @param value to set as the current value
	 */
	public void set(T value)
	{
		this.value = value;
	}
	
	/**
	 * @return the current value or {@code null} if no value is set
	 */
	public T get()
	{
		return value;
	}
}