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
package oughttoprevail.prevailprotocol.session;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import oughttoprevail.prevailprotocol.exception.TooManyDevicesException;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.UserStorage;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;

/**
 * A {@link Session}s manager, managing adding, getting and deleting sessions for a user
 */
public class SessionsManager
{
	/**
	 * Directory of the user who's session is being managed
	 */
	private final Directory userDirectory;
	/**
	 * Map from device identifier to session
	 */
	private final Map<UID, Session> sessions;
	
	/**
	 * Constructs a new {@link SessionsManager} with no sessions (empty).
	 *
	 * @param userDirectory directory of the user who's session is being managed
	 */
	public SessionsManager(Directory userDirectory)
	{
		this.userDirectory = userDirectory;
		this.sessions = new HashMap<>();
	}
	
	/**
	 * Adds the specified session.
	 * This session can later be retrieved {@link #getSession(UID)} where the deviceId is this session's {@link Session#getRecipientUserDeviceUID()}
	 *
	 * @param session to add
	 */
	public void addSession(Session session)
	{
		sessions.put(session.getRecipientUserDeviceUID().getDeviceId(), session);
	}
	
	/**
	 * Removes then deletes the session.
	 *
	 * @param userStorage to delete the session from
	 * @param userDeviceUID of the session
	 * @return whether the session was deleted, {@code false} is returned if the session was not saved in the first place
	 */
	public boolean deleteSession(UserStorage userStorage, UserDeviceUID userDeviceUID)
	{
		Session session = sessions.remove(userDeviceUID.getDeviceId());
		if(session != null)
		{
			userStorage.removeRecipient(userDeviceUID);
			session.deleteSession();
			return true;
		}
		return false;
	}
	
	/**
	 * @param deviceId to get session for
	 * @return the session for this deviceId or {@code null} if there isn't a session for the specified deviceId
	 */
	public Session getSession(UID deviceId)
	{
		return sessions.get(deviceId);
	}
	
	/**
	 * Whether this manager can contain another the current amount of devices incremented by 1 without passing
	 * the limit specified in the specified settings {@link Settings#getMaxDevices()}.
	 *
	 * @param settings to check with
	 * @throws TooManyDevicesException if you can't add another device
	 */
	public void ensureCanAddDevice(Settings settings) throws TooManyDevicesException
	{
		int currentTotalDevices = sessions.size();
		int maxDevices = settings.getMaxDevices();
		if(currentTotalDevices + 1 > maxDevices)
		{
			throw new TooManyDevicesException(String.format(
					"Too many devices to register! (Current total devices: %d, amount of devices to register: %d, max devices: %d)",
					currentTotalDevices,
					1,
					maxDevices));
		}
	}
	
	/**
	 * @return a collection of all the registered sessions
	 */
	public Collection<Session> sessions()
	{
		return sessions.values();
	}
	
	/**
	 * @return the user directory
	 * @see #userDirectory
	 */
	public Directory getUserDirectory()
	{
		return userDirectory;
	}
}