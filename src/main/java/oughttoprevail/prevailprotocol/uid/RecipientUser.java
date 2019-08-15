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

import java.util.ArrayList;
import java.util.List;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A {@link RecipientUser} is in charge of linking all the {@link UID} of a user into a single class.
 */
public class RecipientUser
{
	public static final SerDes<RecipientUser> SER_DES = new SerDes<RecipientUser>()
	{
		@Override
		public void serialize(RecipientUser recipientUser, FieldOutputStream out, Settings settings)
		{
			out.writeObject(recipientUser.getUserId(), settings.getUserIdFactory());
			List<UID> deviceIds = recipientUser.getDeviceIds();
			out.writeInt(deviceIds.size());
			UIDFactory uidFactory = settings.getUIDFactory();
			for(UID deviceId : deviceIds)
			{
				out.writeObject(deviceId, uidFactory);
			}
		}
		
		@Override
		public RecipientUser deserialize(FieldInputStream in, Settings settings)
		{
			UID userId = in.readObject(settings.getUserIdFactory());
			RecipientUser recipientUser = new RecipientUser(userId);
			int totalDeviceIds = in.readInt();
			UIDFactory uidFactory = settings.getUIDFactory();
			for(int i = 0; i < totalDeviceIds; i++)
			{
				UID deviceId = in.readObject(uidFactory);
				recipientUser.add(deviceId);
			}
			return recipientUser;
		}
	};
	
	/**
	 * Adds the specified userDeviceUID as a {@link RecipientUser} to the list.
	 * If a {@link RecipientUser} already exists for the {@link UserDeviceUID#getUserId()} in the specified userDeviceUID then the
	 * {@link UserDeviceUID#getDeviceId()} is added to it, else a {@link RecipientUser} is created for the specified userDeviceUID
	 *
	 * @param storage who created the specified recipientUsers list
	 * @param recipientUsers storage list of {@link RecipientUser}
	 * @param userDeviceUID to add
	 */
	public static void add(Storage storage, List<RecipientUser> recipientUsers, UserDeviceUID userDeviceUID)
	{
		UID userId = userDeviceUID.getUserId();
		for(RecipientUser recipientUser : recipientUsers)
		{
			if(userId.equals(recipientUser.getUserId()))
			{
				recipientUser.add(userDeviceUID.getDeviceId());
				storage.flush();
				return;
			}
		}
		RecipientUser recipientUser = new RecipientUser(userId);
		recipientUser.add(userDeviceUID.getDeviceId());
		recipientUsers.add(recipientUser);
		storage.flush();
	}
	
	/**
	 * The user identifier of the recipient
	 */
	private final UID userId;
	/**
	 * List of device {@link UID}'s of the recipient
	 */
	private final List<UID> deviceIds;
	
	/**
	 * Constructs a new {@link RecipientUser} with the specified userId as it's userId and an empty list for device ids.
	 *
	 * @param userId to be the user identifier of the recipient
	 */
	private RecipientUser(UID userId)
	{
		this.userId = userId;
		this.deviceIds = new ArrayList<>();
	}
	
	/**
	 * Adds the specified deviceId to the deviceIds list.
	 *
	 * @param deviceId to add
	 */
	private void add(UID deviceId)
	{
		deviceIds.add(deviceId);
	}
	
	/**
	 * @return user identifier of the recipient
	 */
	public UID getUserId()
	{
		return userId;
	}
	
	/**
	 * @return list of device {@link UID}'s of the recipient
	 */
	public List<UID> getDeviceIds()
	{
		return deviceIds;
	}
}