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

import java.util.UUID;

/**
 * A {@link UUID} wrapper for {@link UID} interface.
 * Using this is not recommended but if you are already using {@link UUID} and you cannot change this can be used.
 */
public class UUIDWrapper implements UID
{
	/**
	 * The {@link UUID} to wrap
	 */
	private final UUID uuid;
	
	/**
	 * Constructs a new {@link UUIDWrapper} to wrap around the specified uuid.
	 *
	 * @param uuid to wrap
	 */
	public UUIDWrapper(UUID uuid)
	{
		this.uuid = uuid;
	}
	
	/**
	 * @return the wrapped {@link UUID}
	 */
	public UUID getUUID()
	{
		return uuid;
	}
	
	/**
	 * @param obj to compare to this object
	 * @return whether the specified obj is {@link UUIDWrapper} and {@link #getUUID()} equals the {@link #getUUID()} in the specified obj
	 */
	@Override
	public boolean equals(Object obj)
	{
		if(!(obj instanceof UUIDWrapper))
		{
			return false;
		}
		if(obj == this)
		{
			return true;
		}
		return getUUID().equals(((UUIDWrapper) obj).getUUID());
	}
	
	/**
	 * @return the wrapped {@link UUID} string
	 */
	@Override
	public String toString()
	{
		return getUUID().toString();
	}
	
	/**
	 * @return the wrapped {@link UUID} hashCode
	 */
	@Override
	public int hashCode()
	{
		return getUUID().hashCode();
	}
}