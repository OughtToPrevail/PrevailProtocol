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
package oughttoprevail.prevailprotocol.storage;

import java.util.Iterator;
import java.util.List;

import oughttoprevail.prevailprotocol.keys.DataBundle;
import oughttoprevail.prevailprotocol.keys.SavedDataBundle;
import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.uid.RecipientUser;
import oughttoprevail.prevailprotocol.uid.UID;
import oughttoprevail.prevailprotocol.uid.UserDeviceUID;

/**
 * Storage manager for {@link oughttoprevail.prevailprotocol.User}.
 */
public class UserStorage
{
	/**
	 * User storage name
	 */
	private static final String USER_STORAGE = "User";
	/**
	 * User data bundles storage name
	 */
	private static final String USER_DATA_BUNDLES_STORAGE = "UserDataBundles";
	
	/**
	 * Directory of user storage
	 */
	private final Directory directory;
	/**
	 * Storage of this user
	 */
	private final Storage storage;
	/**
	 * Data bundle storage of this user
	 */
	private final Storage dataBundleStorage;
	/**
	 * Device identifier of this user
	 */
	private final Field<UID> deviceId;
	/**
	 * List of recipient users with saved sessions
	 */
	private final List<RecipientUser> recipientUsers;
	/**
	 * The full data bundle, this data bundle is only temporary and should be deleted once sent to the server, then the {@link #savedDataBundle} is
	 * used
	 */
	private final Field<DataBundle> dataBundle;
	/**
	 * The saved data bundle
	 */
	private final SavedDataBundle savedDataBundle;
	
	/**
	 * Constructs a new {@link UserStorage}.
	 *
	 * @param directory to be directory which all storages are created under
	 * @param settings to use
	 */
	public UserStorage(Directory directory, Settings settings)
	{
		this.directory = directory;
		this.storage = directory.storage(USER_STORAGE);
		this.deviceId = storage.getField(settings.getUIDFactory());
		this.recipientUsers = storage.getFieldList(RecipientUser.SER_DES);
		dataBundleStorage = directory.storage(USER_DATA_BUNDLES_STORAGE);
		//create a saved data bundle, there all the fields are
		this.dataBundle = dataBundleStorage.getField(DataBundle.SER_DES);
		this.savedDataBundle = new SavedDataBundle(dataBundleStorage);
	}
	
	/**
	 * Sets the current saved deviceId to the specified deviceId
	 *
	 * @param deviceId to set
	 */
	public void setDeviceId(UID deviceId)
	{
		this.deviceId.set(deviceId);
		storage.flush();
	}
	
	/**
	 * @return the current saved device identifier
	 */
	public UID getDeviceId()
	{
		return deviceId.get();
	}
	
	/**
	 * Adds the specified recipient (userId, deviceId) to the recipient list.
	 *
	 * @param userDeviceUID to be the identifier to add to the recipient list
	 */
	public void addRecipientIds(UserDeviceUID userDeviceUID)
	{
		RecipientUser.add(storage, recipientUsers, userDeviceUID);
	}
	
	/**
	 * Removes the specified userDeviceUID from the recipients list.
	 *
	 * @param userDeviceUID to remove
	 */
	public void removeRecipient(UserDeviceUID userDeviceUID)
	{
		Iterator<RecipientUser> iterator = recipientUsers.iterator();
		while(iterator.hasNext())
		{
			RecipientUser recipientUser = iterator.next();
			//only remove if the userIds match
			if(recipientUser.getUserId().equals(userDeviceUID.getUserId()))
			{
				List<UID> deviceIds = recipientUser.getDeviceIds();
				//if remove returns true then the deviceId was actually stored
				if(deviceIds.remove(userDeviceUID.getDeviceId()))
				{
					//if there are no more devices, then remove the recipient user
					if(deviceIds.isEmpty())
					{
						iterator.remove();
					}
					storage.flush();
				}
				break;
			}
		}
	}
	
	/**
	 * @return a list of all recipient users
	 */
	public List<RecipientUser> getRecipientUsers()
	{
		return recipientUsers;
	}
	
	/**
	 * Stores only the required values of the data bundle then removes the data bundle.
	 */
	public void finishedWithDataBundle()
	{
		savedDataBundle.init(getDataBundle());
		setDataBundle(null);
	}
	
	public SavedDataBundle getSavedDataBundle()
	{
		return savedDataBundle;
	}
	
	/**
	 * Sets the current data bundle
	 *
	 * @param dataBundle to set as the current data bundle
	 */
	public void setDataBundle(DataBundle dataBundle)
	{
		this.dataBundle.set(dataBundle);
		dataBundleStorage.flush();
	}
	
	/**
	 * @return the current data bundle
	 */
	public DataBundle getDataBundle()
	{
		return dataBundle.get();
	}
	
	/**
	 * Deletes all user data
	 */
	public void delete()
	{
		directory.delete();
	}
}