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

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;

/**
 * A {@link UUIDWrapper} implementation at {@link UIDFactory}.
 */
public class UUIDWrapperFactory implements UIDFactory
{
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UID generateUID()
	{
		return new UUIDWrapper(UUID.randomUUID());
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void serialize(UID uid, FieldOutputStream out, Settings settings)
	{
		UUID uuid = ((UUIDWrapper) uid).getUUID();
		out.writeLong(uuid.getMostSignificantBits());
		out.writeLong(uuid.getLeastSignificantBits());
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UID deserialize(FieldInputStream in, Settings settings)
	{
		long mostSignificantBits = in.readLong();
		long leastSignificantBits = in.readLong();
		return new UUIDWrapper(new UUID(mostSignificantBits, leastSignificantBits));
	}
}