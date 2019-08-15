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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;

import oughttoprevail.prevailprotocol.storage.Storage;
import oughttoprevail.prevailprotocol.storage.fields.Field;
import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * An in-memory implementation of {@link Storage}
 */
public class InMemoryStorage implements Storage
{
	/**
	 * @param serDes this parameter doesn't matter
	 * @param <T> type of object to store in the {@link Field}
	 * @return a new {@link Field} with {@code null} as the default value
	 */
	@Override
	public <T> Field<T> getField(SerDes<T> serDes)
	{
		return new Field<>(null);
	}
	
	/**
	 * @param serDes this parameter doesn't matter
	 * @param <T> type of {@link ArrayList}
	 * @return a new {@link ArrayList}
	 */
	@Override
	public <T> List<T> getFieldList(SerDes<T> serDes)
	{
		return new ArrayList<>();
	}
	
	/**
	 * @param serDes this parameter doesn't matter
	 * @param <T> type of {@link ArrayDeque}
	 * @return a new {@link ArrayDeque}
	 */
	@Override
	public <T> Queue<T> getFieldQueue(SerDes<T> serDes)
	{
		return new ArrayDeque<>();
	}
	
	/**
	 * Empty method
	 */
	@Override
	public void flush()
	{
	
	}
}