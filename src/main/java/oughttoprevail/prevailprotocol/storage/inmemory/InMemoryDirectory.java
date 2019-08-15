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
package oughttoprevail.prevailprotocol.storage.inmemory;

import oughttoprevail.prevailprotocol.storage.Directory;
import oughttoprevail.prevailprotocol.storage.Storage;

/**
 * A in-memory implementation of {@link Directory}.
 */
public class InMemoryDirectory implements Directory
{
	/**
	 * In-memory storage
	 */
	private static final InMemoryStorage STORAGE = new InMemoryStorage();
	
	/**
	 * @param storageName this parameter doesn't matter
	 * @return a in-memory storage
	 */
	@Override
	public Storage storage(String storageName)
	{
		return STORAGE;
	}
	
	/**
	 * @param directoryName this parameter doesn't matter
	 * @return this
	 */
	@Override
	public Directory directory(String directoryName)
	{
		return this;
	}
	
	/**
	 * Empty method
	 */
	@Override
	public void delete()
	{
	
	}
	
	/**
	 * Empty method
	 */
	@Override
	public void finish()
	{
	
	}
}