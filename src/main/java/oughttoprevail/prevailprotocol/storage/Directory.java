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

import oughttoprevail.prevailprotocol.exception.NotMainDirectoryException;
import oughttoprevail.prevailprotocol.storage.inmemory.InMemoryDirectory;

/**
 * A {@link Directory} is responsible for creating storages, a directory is meant to make sure that if a storageName repeats, it will not go to
 * the same storage because the directories path don't match.
 */
public interface Directory
{
	/**
	 * @return a in-memory directory, this means that this directory will save no values in storage, this is useful for applications who wish to not
	 * store any data on the device.
	 */
	static Directory newInMemoryDirectory()
	{
		return new InMemoryDirectory();
	}
	
	/**
	 * @param storageName to be the new storage name (identifier name of this storage in this directory)
	 * @return a new {@link Storage} with the specified storageName
	 */
	Storage storage(String storageName);
	
	/**
	 * @param directoryName for the new directory
	 * @return a new {@link Directory} with the specified directoryName
	 */
	Directory directory(String directoryName);
	
	/**
	 * Deletes this directory and all underlying directories and storages.
	 *
	 * <b>NOTE: it is recommended to also delete all in-memory {@link oughttoprevail.prevailprotocol.storage.fields.Field} underlying values</b>
	 */
	void delete();
	
	/**
	 * Finishes the use of this directory.
	 *
	 * @throws NotMainDirectoryException if this directory is not the main (first) directory
	 */
	void finish() throws NotMainDirectoryException;
}