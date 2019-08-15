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
 * A user and device identifiers.
 */
public class UserDeviceUID
{
	/**
	 * User identifier
	 */
	private final UID userId;
	/**
	 * Device identifier
	 */
	private final UID deviceId;
	
	/**
	 * Constructs a new {@link UserDeviceUID}.
	 *
	 * @param userId to be the userId value
	 * @param deviceId to be the deviceId value
	 */
	public UserDeviceUID(UID userId, UID deviceId)
	{
		this.userId = userId;
		this.deviceId = deviceId;
	}
	
	/**
	 * @return user identifier
	 */
	public UID getUserId()
	{
		return userId;
	}
	
	/**
	 * @return device identifier
	 */
	public UID getDeviceId()
	{
		return deviceId;
	}
	
	private static final String CLASS_NAME = UserDeviceUID.class.getSimpleName();
	
	/**
	 * @return this {@link UserDeviceUID} represented as {@link String}
	 */
	@Override
	public String toString()
	{
		return CLASS_NAME + "(UserId: " + userId.toString() + ", DeviceId: " + deviceId.toString() + ")";
	}
	
	/**
	 * @param obj to compare to this object
	 * @return if the specified obj is a {@link UserDeviceUID} and the {@link #getUserId()} and {@link #getDeviceId()} equals the {@link #getUserId()}
	 * and {@link #getDeviceId()} in the specified obj
	 */
	@Override
	public boolean equals(Object obj)
	{
		if(!(obj instanceof UserDeviceUID))
		{
			return false;
		}
		if(obj == this)
		{
			return true;
		}
		UserDeviceUID other = (UserDeviceUID) obj;
		return other.getUserId().equals(getUserId()) && other.getDeviceId().equals(getDeviceId());
	}
	
	/**
	 * @return the hashCode of the {@link #getUserId()} and {@link #getDeviceId()}
	 */
	@Override
	public int hashCode()
	{
		return Util.hashCode(getUserId(), getDeviceId());
	}
}