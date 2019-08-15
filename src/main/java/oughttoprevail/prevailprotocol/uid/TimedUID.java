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

import oughttoprevail.prevailprotocol.util.Util;

/**
 * A {@link TimedUID} is a time-based implementation of {@link UID}.
 * A {@link TimedUID} is completely unique (cannot generate the same value twice on the same {@link UIDFactory}).
 * Every {@link TimedUID} is made out of a long (time) represented in milliseconds and a counter (short) with the initial value of
 * {@link Short#MIN_VALUE} (together it is 12 bytes).
 */
public class TimedUID implements UID
{
	/**
	 * Time of this {@link UID}
	 */
	private final long time;
	/**
	 * Counter unique for the time
	 */
	private final short counter;
	
	/**
	 * Constructs a new {@link TimedUID} with the specified time and specified counter.
	 *
	 * @param time of this {@link UID}
	 * @param counter unique for the specified time
	 */
	TimedUID(long time, short counter)
	{
		this.time = time;
		this.counter = counter;
	}
	
	long getTime()
	{
		return time;
	}
	
	short getCounter()
	{
		return counter;
	}
	
	/**
	 * Keep a string representation to save string calculation time
	 */
	private String asString;
	
	/**
	 * @return this {@link TimedUID} represented as a {@link String}
	 */
	@Override
	public String toString()
	{
		if(asString == null)
		{
			asString = String.valueOf(getTime()) + getCounter();
		}
		return asString;
	}
	
	/**
	 * @param obj to compare to this object
	 * @return if the specified obj is a {@link TimedUID} and the time and counter equals the time and counter in the specified obj
	 */
	@Override
	public boolean equals(Object obj)
	{
		if(!(obj instanceof TimedUID))
		{
			return false;
		}
		if(obj == this)
		{
			return true;
		}
		TimedUID other = (TimedUID) obj;
		return other.getTime() == getTime() && other.getCounter() == getCounter();
	}
	
	/**
	 * @return the hashCode of the time and counter
	 */
	@Override
	public int hashCode()
	{
		return Util.hashCode(getTime(), getCounter());
	}
}