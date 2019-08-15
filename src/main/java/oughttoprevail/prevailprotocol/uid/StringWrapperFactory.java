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

import java.nio.charset.Charset;

import oughttoprevail.prevailprotocol.settings.Settings;
import oughttoprevail.prevailprotocol.storage.fields.FieldInputStream;
import oughttoprevail.prevailprotocol.storage.fields.FieldOutputStream;

/**
 * A {@link StringWrapper} implementation of the {@link UIDFactory}
 */
public class StringWrapperFactory implements UIDFactory
{
	/**
	 * Charset of the strings which will be serialized and deserialized
	 */
	private final Charset stringCharset;
	
	/**
	 * Constructs a new {@link StringWrapperFactory}.
	 *
	 * @param stringCharset {@link #stringCharset}
	 */
	public StringWrapperFactory(Charset stringCharset)
	{
		this.stringCharset = stringCharset;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UID generateUID()
	{
		throw new UnsupportedOperationException("UID generation is not supported!");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void serialize(UID uid, FieldOutputStream out, Settings settings)
	{
		StringWrapper stringUID = (StringWrapper) uid;
		out.writeBytes(stringUID.getValue().getBytes(stringCharset));
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public UID deserialize(FieldInputStream in, Settings settings)
	{
		byte[] stringBytes = in.readBytes();
		return new StringWrapper(new String(stringBytes, stringCharset));
	}
}