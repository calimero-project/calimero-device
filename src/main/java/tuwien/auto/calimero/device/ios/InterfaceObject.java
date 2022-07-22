/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2022 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package tuwien.auto.calimero.device.ios;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.cemi.CEMIDevMgmt.ErrorCodes;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer.IosResourceHandler;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;

/**
 * An interface object is a common structure to hold KNX properties.
 * <p>
 * An interface object is configured to a certain interface object type, with the type either being
 * a predefined type using one of the type constants listed by this class, or a user-defined object
 * type.<br>
 * KNX properties are usually associated to be used within a specific object type (stated in the
 * corresponding property definition), or can be used in interface objects of any type (with such
 * KNX properties referred to as 'global' properties in their definition).
 * <p>
 * Each interface object contains the mandatory property
 * {@link tuwien.auto.calimero.mgmt.PropertyAccess.PID#OBJECT_TYPE} at property index 0, i.e., as
 * its first property entry.
 * <p>
 * Interface objects are managed by an {@link InterfaceObjectServer}, with each interface object
 * uniquely identified by its object index ({@link #getIndex()}.<br>
 * KNX properties contained in an interface object are usually accessed and modified using KNX
 * property services.
 *
 * @author B. Malinowsky
 */
public class InterfaceObject
{
	/** Interface object type 'device object' ({@value DEVICE_OBJECT}). */
	public static final int DEVICE_OBJECT = 0;

	/** Interface object type 'address table object' ({@value ADDRESSTABLE_OBJECT}). */
	public static final int ADDRESSTABLE_OBJECT = 1;

	/**
	 * Interface object type 'association table object' ({@value ASSOCIATIONTABLE_OBJECT}).
	 */
	public static final int ASSOCIATIONTABLE_OBJECT = 2;

	/**
	 * Interface object type 'application program object' ({@value APPLICATIONPROGRAM_OBJECT}).
	 */
	public static final int APPLICATIONPROGRAM_OBJECT = 3;

	/**
	 * @deprecated Use {@link #APPLICATION_PROGRAM2}
	 */
	@Deprecated(forRemoval = true)
	public static final int INTERFACEPROGRAM_OBJECT = 4;

	/**
	 * Interface object type 'application program 2 object' ({@value}).
	 */
	public static final int APPLICATION_PROGRAM2 = 4;

	// never used in practice
	// public static final int EIB_OBJECT_ASSOCIATIONTABLE_OBJECT = 5;

	/**
	 * Interface object type 'router object' ({@value ROUTER_OBJECT}).
	 */
	public static final int ROUTER_OBJECT = 6;

	/**
	 * Interface object type 'LTE address filter table object' ({@value
	 * LTE_ADDRESS_FILTER_TABLE_OBJECT}).
	 */
	public static final int LTE_ADDRESS_FILTER_TABLE_OBJECT = 7;

	/** Interface object type 'cEMI server object' ({@value CEMI_SERVER_OBJECT}). */
	public static final int CEMI_SERVER_OBJECT = 8;

	/**
	 * Interface object type 'group object table object' ({@value GROUP_OBJECT_TABLE_OBJECT}).
	 */
	public static final int GROUP_OBJECT_TABLE_OBJECT = 9;

	/** Interface object type 'polling master' ({@value POLLING_MASTER}). */
	public static final int POLLING_MASTER = 10;

	/**
	 * Interface object type 'KNXnet/IP parameter object' ({@value KNXNETIP_PARAMETER_OBJECT}).
	 */
	public static final int KNXNETIP_PARAMETER_OBJECT = 11;

	/** Interface object type 'application controller' ({@value APPLICATION_CONTROLLER}). */
	public static final int APPLICATION_CONTROLLER = 12;

	/** Interface object type 'file server object' ({@value FILE_SERVER_OBJECT}). */
	public static final int FILE_SERVER_OBJECT = 13;

	/** Interface object type 'security' ({@value SECURITY_OBJECT}). */
	public static final int SECURITY_OBJECT = 17;

	/** Interface object type 'RF medium object' ({@value RF_MEDIUM_OBJECT}). */
	public static final int RF_MEDIUM_OBJECT = 19;

	// list holding Description objects or null entries
	private final List<Description> descriptions = new ArrayList<>();
	private final Map<Integer, Description> pidToDescription = new HashMap<>();
	final Map<PropertyKey, byte[]> values = new HashMap<>();

	private final int type;
	private final Map<PropertyKey, Property> definitions;
	private volatile int idx;

	volatile InterfaceObjectServer ios;

	/**
	 * Creates a new interface object of the specified object type.
	 *
	 * @param objectType either one of the predefined interface object types listed by this class,
	 *        or a user specific object type
	 */
	public InterfaceObject(final int objectType)
	{
		this(objectType, Map.of());
	}

	InterfaceObject(final int objectType, final int index, final Map<PropertyKey, Property> definitions) {
		this(objectType, definitions);
		setIndex(index);
	}

	private InterfaceObject(final int objectType, final Map<PropertyKey, Property> definitions) {
		type = objectType;
		this.definitions = definitions;
	}

	/**
	 * Returns the type of this interface object.
	 * <p>
	 * The type is either one of the predefined interface object types listed by this class, or a
	 * user specific object type.
	 *
	 * @return interface object type as int
	 */
	public int getType()
	{
		return type;
	}

	/**
	 * Returns a human readable representation of the interface object's type.
	 *
	 * @return interface object type as string
	 */
	public String getTypeName()
	{
		return PropertyClient.getObjectTypeName(type);
	}

	/**
	 * Returns the current position of this interface object within the array of interface objects
	 * in the interface object server.
	 *
	 * @return zero based index as int
	 */
	public int getIndex()
	{
		return idx;
	}

	void load(final IosResourceHandler rh) throws KNXException
	{
		final List<Description> loadDescriptions = new ArrayList<>();
		final List<byte[]> loadValues = new ArrayList<>();
		rh.loadProperties(loadDescriptions, loadValues);

		final Iterator<byte[]> k = loadValues.iterator();
		for (final Iterator<Description> i = loadDescriptions.iterator(); i.hasNext()
				&& k.hasNext();) {
			final Description d = i.next();
			final byte[] v = k.next();

			setDescription(d);
			values.put(new PropertyKey(d.getObjectType(), d.getPID()), v);
		}
	}

	void save(final IosResourceHandler rh) throws KNXException
	{
		// list to save with descriptions, containing no null entries
		final List<Description> saveDesc = new ArrayList<>(descriptions);
		saveDesc.removeAll(Arrays.asList(new Object[] { null }));
		// list to save with values
		final List<byte[]> saveVal = new ArrayList<>();
		// values with no description
		final Map<PropertyKey, byte[]> remaining = new HashMap<>(values);

		final byte[] empty = new byte[0];
		for (final Iterator<Description> i = saveDesc.iterator(); i.hasNext();) {
			final Description d = i.next();
			final PropertyKey key = new PropertyKey(d.getObjectType(), d.getPID());
			final byte[] data = values.get(key);
			// descriptions with no values get an empty array assigned
			if (data == null)
				saveVal.add(empty);
			else {
				remaining.remove(key);
				saveVal.add(data.clone());
			}
		}
		// add values where no description was set, creating a default description
		for (final Iterator<PropertyKey> i = remaining.keySet().iterator(); i.hasNext();) {
			final PropertyKey key = i.next();
			saveDesc.add(new Description(idx, type, key.getPID(), saveVal.size(), 0, true, 0, 0, 0, 0));
			saveVal.add(remaining.get(key).clone());
		}
		// save them
		rh.saveProperties(saveDesc, saveVal);
	}

	@Override
	public String toString()
	{
		return getTypeName() + " (index " + idx + ")";
	}

	byte[] getProperty(final int pid, final int start, final int elements) throws KnxPropertyException {
		final var desc = findByPid(pid);
		if (desc == null)
			throw new KnxPropertyException(
					"no property ID " + pid + " in " + getTypeName() + " (index " + getIndex() + ")",
					ErrorCodes.VOID_DP);

		final byte[] bytes = values.get(new PropertyKey(getType(), pid));
		if (start == 0) {
			if (elements > 1)
				throw new KnxPropertyException("current number of elements consists of only 1 element",
						ErrorCodes.UNSPECIFIED_ERROR);

			return new byte[] { bytes[0], bytes[1] };
		}

		final int currElems = (bytes[0] & 0xff) << 8 | (bytes[1] & 0xff);
		// treat MAX_VALUE special, in that it returns all elements in range [start, currElems]
		final int actualElements = elements == Integer.MAX_VALUE ? (currElems - start + 1) : elements;
		final int size = start + actualElements - 1;
		if (currElems < size)
			throw new KnxPropertyException(err(pid, "requested elements [" + start + ".." + size + "] exceed past last property value"),
					ErrorCodes.PROP_INDEX_RANGE_ERROR);
		final int typeSize = PropertyTypes.bitSize(desc.getPDT()).map(bits -> Math.max(bits, 8) / 8)
				.orElseGet(() -> (bytes.length - 2) / currElems);
		final byte[] data = new byte[actualElements * typeSize];
		int d = 0;
		for (int i = 2 + (start - 1) * typeSize; i < 2 + size * typeSize; ++i)
			data[d++] = bytes[i];
		return data;
	}

	private String err(final int propertyId, final String msg) {
		final var p = getDefinition(propertyId);
		final String s = p != null ? " (" + p.getName() + ")" : "";
		return String.format("%d|%d%s %s", getIndex(), propertyId, s, msg);
	}

	boolean setProperty(final int pid, final int start, final int elements, final byte[] data, final boolean strictMode)
			throws KnxPropertyException {
		final PropertyKey key = new PropertyKey(getType(), pid);
		byte[] bytes = values.get(key);

		if (start == 0) {
			// Document Application IF Layer (03/04/01) v1.1, 4.2.1:
			// Write value 0 on index 0 to reset element values
			if (elements == 1 && data.length == 2 && data[0] == 0 && data[1] == 0) {
				truncateValueArray(pid, 0);
				return false;
			}
			throw new KnxPropertyException("set current number of elements", ErrorCodes.READ_ONLY);
		}

		// try to get property type size, using the following order:
		// 1) query description
		// 2) query definitions
		// 3) use dptId
		// 4) trust input parameters and calculate type size

		int pdt = -1;
		Optional<String> dptId = Optional.empty();
		Description d = null;
		boolean createDescription = false;
		try {
			d = new Description(getType(), getDescription(pid, 0));
			pdt = d.getPDT();
		}
		catch (final KnxPropertyException e) {
			if (strictMode)
				throw new KnxPropertyException(
						"strict mode: no description found for " + getTypeName() + " PID " + pid);
			createDescription = true;
			final Property p = getDefinition(pid);
			if (p != null) {
				pdt = p.getPDT();
				dptId = p.dpt();
			}
		}

		final var id = dptId;
		final int typeSize = PropertyTypes.bitSize(pdt).or(() -> id.flatMap(InterfaceObject::dptBitSize))
				.map(size -> Math.max(size / 8, 1)).orElseGet(() -> elements > 0 ? data.length / elements : 1);

		if (elements > 0 && typeSize != data.length / elements) {
			var typeName = PropertyClient.getObjectTypeName(type);
			if (typeName.isEmpty())
				typeName = "OT " + type;
			throw new KnxPropertyException(
					typeName + " PID " + pid + " property type size is " + typeSize + ", not " + data.length / elements,
					ErrorCodes.TYPE_CONFLICT);
		}

		// I dynamically increase the value array if the new element size exceeds
		// the current element size, and adjust the current element number
		// correspondingly.
		final int size = start + elements - 1;
		if (bytes == null || size > (bytes.length - 2) / typeSize) {
			final int maxElements = d == null ? elements : d.getMaxElements();
			if (size > maxElements)
				throw new KnxPropertyException("property values index range [" + start + "..." + size + "] exceeds "
						+ maxElements + " maximum elements", ErrorCodes.PROP_INDEX_RANGE_ERROR);
			// create resized array
			final byte[] resize = new byte[2 + size * typeSize];
			resize[0] = (byte) (size >> 8);
			resize[1] = (byte) size;
			// copy over existing values, if any
			if (bytes != null)
				for (int i = 2; i < bytes.length; ++i)
					resize[i] = bytes[i];

			values.put(key, resize);
			bytes = resize;
		}
		int k = 0;
		boolean changed = false;
		for (int i = 2 + (start - 1) * typeSize; i < 2 + size * typeSize; ++i) {
			changed |= bytes[i] != data[k];
			bytes[i] = data[k++];
		}

		// make sure we provide a minimum description
		if (createDescription)
			createNewDescription(pid, true);

		return changed;
	}

	byte[] getDescription(final int pid, final int propIndex) throws KnxPropertyException {
		Description d = null;
		if (pid != 0)
			d = findByPid(pid);
		else if (propIndex < descriptions.size())
			d = descriptions.get(propIndex);

		if (d != null) {
			return new Description(getIndex(), d.getObjectType(), d.getPID(), d.getPropIndex(), d.getPDT(),
					d.isWriteEnabled(), 0, d.getMaxElements(), d.getReadLevel(), d.getWriteLevel()).toByteArray();
		}

		var typeName = getTypeName();
		if (typeName.isEmpty())
			typeName = "OT " + type;
		throw new KnxPropertyException("no description found for " + typeName
				+ (pid != 0 ? " PID " + pid : " property index " + propIndex));
	}

	private Description findByPid(final int pid) {
		return pidToDescription.get(pid);
	}

	int findFreeSlot() {
		int i = descriptions.indexOf(null);
		if (i == -1)
			i = descriptions.size();
		return i;
	}

	void setDescription(final Description d, final boolean allowCorrections) {
		// do some validity checks before setting the description
		// tells us whether we have to create a corrected description before inserting
		boolean adjust = false;

		if (d.getObjectType() != type) {
			if (!allowCorrections)
				throw new KNXIllegalArgumentException("interface object type differs");
			adjust = true;
		}

		int idx;
		int existingIdx = 0;
		int pdt = 0;
		// check if a description already exists
		final Description chk = findByPid(d.getPID());
		if (chk != null) {
			existingIdx = chk.getPropIndex();
			idx = existingIdx;
			pdt = chk.getPDT();
		}
		else {
			// no existing description, find an empty position index
			idx = findFreeSlot();
		}
		// ensure object type property is on first position
		if (d.getPID() == PID.OBJECT_TYPE) {
			if (d.getPropIndex() != 0) {
				if (!allowCorrections)
					throw new KNXIllegalArgumentException("property 'object type' (PID 1) only allowed at index 0");
				adjust = true;
				idx = 0;
			}
		}
		else if (d.getPropIndex() == 0) {
			if (!allowCorrections)
				throw new KNXIllegalArgumentException("only property 'object type' (PID 1) allowed at index 0");
			adjust = true;
		}
		else
			idx = d.getPropIndex();

		if (d.getMaxElements() < d.getCurrentElements()) {
			if (!allowCorrections)
				throw new KNXIllegalArgumentException("maximum elements less than current elements");
		}

		if (d.getPDT() == 0 && allowCorrections) {
			// if no existing description or no pdt was set
			if (pdt == 0) {
				final Property p = getDefinition(d.getPID());
				if (p != null)
					pdt = p.getPDT();
			}
			if (pdt != 0)
				adjust = true;
		}
		else
			pdt = d.getPDT();

		// check if we have to remove an existing description (which might be located at
		// a different index)
		// Note: existingIdx = 0 refers to a non existing description and an existing
		// description at index 0
		// But index 0 is a special case because the object-type property description is
		// fixed to that position; therefore, we never have to remove it, it is always
		// replaced correctly
		if (existingIdx != 0)
			removeDescription(existingIdx);

		// NB: the current elements field used here is meaningless
		final var set = adjust ? new Description(d.getObjectIndex(), type, d.getPID(), idx, pdt, d.isWriteEnabled(),
				d.getCurrentElements(), d.getMaxElements(), d.getReadLevel(), d.getWriteLevel()) : d;
		setDescription(set);
	}

	// this method also ensures the value array is truncated accordingly
	void setDescription(final Description d)
	{
		// increase array size until we can insert at requested index
		final int index = d.getPropIndex();
		while (index >= descriptions.size())
			descriptions.add(null);
		descriptions.set(index, d);
		// truncate property elements based on max. allowed elements
		truncateValueArray(d.getPID(), d.getMaxElements());
		pidToDescription.put(d.getPID(), d);
	}

	void createNewDescription(final int pid, final boolean writeEnabled) {
		final byte[] data = values.get(new PropertyKey(getType(), pid));
		final int elems = (data[0] & 0xff) << 8 | (data[1] & 0xff);
		final int maxElems = Math.max(elems, 1);

		int pdt = -1;
		final Property p = getDefinition(pid);
		if (p != null)
			pdt = p.getPDT();
		if (pdt == -1 && elems > 0) {
			final int size = (data.length - 2) / elems;
			pdt = PropertyTypes.PDT_GENERIC_01 + size - 1;
		}

		final int pIndex = descriptions.size();
		final boolean writable = p != null ? !p.readOnly() : writeEnabled;
		// level is between 0 (max. access rights required) and 3 or 15 (min. rights required)
		final int readLevel = p != null ? p.readLevel() : 0;
		final int writeLevel = p != null ? Math.max(0, p.writeLevel()) : 0;
		final Description d = new Description(getIndex(), getType(), pid, pIndex, pdt, writable, elems, maxElems,
				readLevel, writeLevel);
		descriptions.add(d);
		pidToDescription.put(pid, d);
	}

	void removeDescription(final int existingIdx) {
		descriptions.set(existingIdx, null);
	}

	void setIndex(final int index)
	{
		idx = index;
	}

	void truncateValueArray(final int pid, final int maxElements)
	{
		final PropertyKey key = new PropertyKey(getType(), pid);
		final byte[] v = values.get(key);
		if (maxElements == 0 || v == null) {
			values.put(key, new byte[2]);
			return;
		}
		// extract first two bytes
		final int elems = (v[0] & 0xff) << 8 | (v[1] & 0xff);
		if (elems > maxElements) {
			final int elemsFieldSize = 2;
			final int typeSize = (v.length - elemsFieldSize) / elems;
			final byte[] ba = new byte[elemsFieldSize + maxElements * typeSize];
			System.arraycopy(v, elemsFieldSize, ba, elemsFieldSize, ba.length - elemsFieldSize);
			ba[0] = (byte) (maxElements >> 8);
			ba[1] = (byte) maxElements;
			values.put(key, ba);
		}
	}

	void firePropertyChanged(final int propertyId, final int start, final int elements, final byte[] data) {
		final var server = ios;
		if (server != null)
			server.firePropertyChanged(this, propertyId, start, elements, data);
	}

	private Property getDefinition(final int pid) {
		Property p = definitions.get(new PropertyKey(type, pid));
		if (p == null && pid < 50)
			p = definitions.get(new PropertyKey(pid));
		return p;
	}

	private static Optional<Integer> dptBitSize(final String dptId) {
		try {
			return Optional.of(TranslatorTypes.createTranslator(0, dptId).bitSize());
		}
		catch (final KNXException e) {}
		return Optional.empty();
	}

	private static int toInt(final byte[] data)
	{
		if (data.length == 1)
			return data[0] & 0xff;
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | (data[1] & 0xff);
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | (data[3] & 0xff);
	}
}
