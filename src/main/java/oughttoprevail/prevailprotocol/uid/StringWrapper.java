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
package oughttoprevail.prevailprotocol.uid;

import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * A {@link String} wrapper for {@link UID} interface.
 * Using a {@link StringWrapper} is only supported as a user identifier and not as a setting's {@link Settings#getUserIdFactory()}.
 */
public class StringWrapper implements UID
{
	/**
	 * Wrapped string value
	 */
	private final String value;
	
	/**
	 * Constructs a new {@link StringWrapper} to wrap around the specified value
	 *
	 * @param value to wrap
	 */
	public StringWrapper(String value)
	{
		this.value = value;
	}
	
	/**
	 * @return the wrapped value
	 */
	public String getValue()
	{
		return value;
	}
	
	/**
	 * Equals to {@link #getValue()}
	 */
	@Override
	public String toString()
	{
		return getValue();
	}
	
	/**
	 * @param obj to compare to this object
	 * @return whether the specified obj is {@link StringWrapper} and this {@link #getValue()} equals the {@link #getValue()} in the specified obj
	 */
	@Override
	public boolean equals(Object obj)
	{
		if(!(obj instanceof StringWrapper))
		{
			return false;
		}
		if(obj == this)
		{
			return true;
		}
		String objValue = ((StringWrapper) obj).getValue();
		return getValue().equals(objValue);
	}
	
	/**
	 * @return the wrapped {@link String} hashCode
	 */
	@Override
	public int hashCode()
	{
		return getValue().hashCode();
	}
}