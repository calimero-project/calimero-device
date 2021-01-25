/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2021 B. Malinowsky

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

import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAdapter;
import tuwien.auto.calimero.mgmt.PropertyClient;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.mgmt.PropertyClient.ResourceHandler;
import tuwien.auto.calimero.mgmt.PropertyClient.XmlPropertyDefinitions;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XmlInputFactory;
import tuwien.auto.calimero.xml.XmlOutputFactory;
import tuwien.auto.calimero.xml.XmlReader;
import tuwien.auto.calimero.xml.XmlWriter;

/**
 * An interface object server holds {@link InterfaceObject}s and offers property services for the
 * contained KNX properties.
 * <p>
 * Property access through the property services provided by this class are the preferred way for
 * property access.<br>
 * The interface server provides the {@link IosResourceHandler} to load and save interface object
 * server information from and to a resource. The default resource handler implementation uses an
 * xml format layout.
 * <p>
 * A server instance can maintain KNX property definitions. Such property definitions are used to
 * fill in default values for property descriptions and validation purposes on property access.
 * Definitions are loaded from a definition resource, e.g., a file, handed to the server.<br>
 * For definition resources, by default an xml resource handler implementing the
 * {@link tuwien.auto.calimero.mgmt.PropertyClient.ResourceHandler} interface is used. It supports
 * the same xml schema layout as the default resource handler in the {@link PropertyClient}.
 *
 * @author B. Malinowsky
 */
public class InterfaceObjectServer implements PropertyAccess
{
	private final Logger logger = LogService.getLogger("calimero.device.Interface Object Server");

	private IosResourceHandler rh;

	// the list of interface objects is not expected to change frequently
	private final List<InterfaceObject> objects = new ArrayList<>();

	private final IosAdapter adapter = new IosAdapter();
	private final PropertyClient client;

	private final boolean strictMode;

	private final EventListeners<InterfaceObjectServerListener> listeners = new EventListeners<>(logger);

	/**
	 * Creates a new interface object server.
	 * <p>
	 * The strict property mode determines the handling of access to properties by the server. If
	 * strict mode is enabled, standard conform procedures are enforced, if disabled, the server
	 * allows a more lazy, convenient, access to properties.<br>
	 * This flag affects behavior for the following property services<br>
	 * - in strict mode:
	 * <ul>
	 * <li>set property: only allowed if corresponding property description exists</li>
	 * </ul>
	 * - in lazy mode:
	 * <ul>
	 * <li>set property: allowed even if corresponding property description does not exist</li>
	 * </ul>
	 * This constructor creates and initializes the following Interface Objects:<br>
	 * - InterfaceObject.DEVICE_OBJECT<br>
	 * See {@link #addInterfaceObject(int)} for details on creation.
	 *
	 * @param strictPropertyMode <code>true</code> if server shall enforce strict mode,
	 *        <code>false</code> otherwise
	 */
	public InterfaceObjectServer(final boolean strictPropertyMode)
	{
		strictMode = strictPropertyMode;
		try {
			client = new PropertyClient(adapter);
		}
		catch (final KNXFormatException e) {
			// Don't propagate this checked exception type: it indicates that we requested an
			// unsupported DPT. But the property client DPT is known and supported in the standard
			// set of Calimero translators.
			throw new KNXIllegalArgumentException("cannot create property client", e);
		}

		try {
			final String propertyDefinitions = "/properties.xml";
			final URL resource = getClass().getResource(propertyDefinitions);
			if (resource != null)
				loadDefinitions(resource.toString());
		}
		catch (KNXException | KNXMLException | UncheckedIOException e) {
			// using the default resource ID, we cannot expect to always find the resource
			logger.info("could not load the Interface Object Server KNX property definitions ({})", e.getMessage());
		}

		// AN033 3.2.6: minimum required interface objects for a cEMI server
		// are a device object and a cEMI server object (cEMI server is added by device)
		addInterfaceObject(InterfaceObject.DEVICE_OBJECT);
	}

	/**
	 * Sets a new default Interface Object Server resource handler used in the load/save methods by
	 * this server.
	 * <p>
	 * By default, an xml property file handler is used.
	 *
	 * @param handler the new property resource handler, or <code>null</code> to use the default
	 *        handler
	 */
	public synchronized void setResourceHandler(final IosResourceHandler handler)
	{
		rh = handler;
	}

	/**
	 * Loads property definitions from a resource for use by this IOS. By default, this method uses
	 * {@link XmlPropertyDefinitions} as resource handler.
	 *
	 * @param resource the identifier of a resource to load
	 * @throws KNXException on errors in the property resource handler
	 */
	public void loadDefinitions(final String resource) throws KNXException
	{
		final ResourceHandler handler = new XmlPropertyDefinitions();
		client.addDefinitions(handler.load(resource));
	}

	public Map<PropertyKey, Property> propertyDefinitions() {
		return client.getDefinitions();
	}

	/**
	 * Loads interface objects from the specified resource into this interface object server using
	 * the resource handler set by
	 * {@link #setResourceHandler(InterfaceObjectServer.IosResourceHandler)}.
	 * <p>
	 * Any interface objects previously added to this IOS instance are not affected.
	 *
	 * @param resource resource storage location identifier passed to the used IOS resource handler
	 * @throws KNXException on problems loading the interface objects, as thrown by the IOS resource
	 *         handler
	 */
	public void loadInterfaceObjects(final String resource) throws KNXException {
		load(resource);
	}

	public void loadInterfaceObjects(final InputStream is) throws KNXException {
		load(is);
	}

	private void load(final Object o) throws KNXException {
		final IosResourceHandler h;
		synchronized (this) {
			if (rh == null)
				setResourceHandler(new XmlSerializer(logger, client.getDefinitions()));
			h = rh;
		}
		final var list = o instanceof String ? h.loadInterfaceObjects((String) o)
											 : h.loadInterfaceObjects((InputStream) o);
		// we insert the objects in iteration order, but correcting the loaded interface
		// object to match the insertion index. this is to avoid null entries in the
		// objects list.
		for (final InterfaceObject io : list) {
			synchronized (objects) {
				final int index = objects.size();
				io.setIndex(index);
				objects.add(io);
			}
			// necessary to update index property value to match io index
			initIoProperties(io, false);
		}
		updateIoList();
	}

	/**
	 * Saves the interface objects contained in this interface object server to the specified
	 * resource using the resource handler set by
	 * {@link #setResourceHandler(InterfaceObjectServer.IosResourceHandler)}.
	 *
	 * @param resource resource storage location identifier passed to the used IOS resource handler
	 * @throws KNXException on problems saving the interface objects, as thrown by the IOS resource
	 *         handler
	 */
	public void saveInterfaceObjects(final String resource) throws KNXException
	{
		final IosResourceHandler h;
		synchronized (this) {
			if (rh == null)
				setResourceHandler(new XmlSerializer(logger, client.getDefinitions()));
			h = rh;
		}
		final InterfaceObject[] objects = getInterfaceObjects();
		h.saveInterfaceObjects(resource, Arrays.asList(objects));
	}

	public void saveInterfaceObjects(final OutputStream os) throws KNXException {
		final IosResourceHandler h;
		synchronized (this) {
			if (rh == null)
				setResourceHandler(new XmlSerializer(logger, client.getDefinitions()));
			h = rh;
		}
		final InterfaceObject[] objects = getInterfaceObjects();
		h.saveInterfaceObjects(os, Arrays.asList(objects));
	}

	@SuppressWarnings("unchecked")
	public <T extends InterfaceObject> T lookup(final int objectType, final int objectInstance)
			throws KnxPropertyException {
		synchronized (objects) {
			int inst = 0;
			for (final Iterator<InterfaceObject> i = objects.iterator(); i.hasNext();) {
				final InterfaceObject io = i.next();
				if (io.getType() == objectType && ++inst == objectInstance)
					return (T) io;
			}
			String ot = PropertyClient.getObjectTypeName(objectType);
			if (ot.isEmpty())
				ot = "object type " + objectType;
			throw new KnxPropertyException("no object instance " + objectInstance + " of " + ot + " in IOS");
		}
	}

	/**
	 * Returns an array with interface objects currently managed by the interface object server.
	 * <p>
	 * Modifications to the array do not alter the internal list of interface objects kept by the
	 * server.<br>
	 * If the server does not contain any interface objects, an array of length 0 is returned.
	 *
	 * @return array of interface objects
	 */
	public InterfaceObject[] getInterfaceObjects()
	{
		synchronized (objects) {
			return objects.toArray(new InterfaceObject[objects.size()]);
		}
	}

	/**
	 * Adds an interface object of the specified type to this Interface Object Server.
	 * <p>
	 * A new interface object of that type is created and added at the end of Interface Objects
	 * contained in the IOS, with its index set to the chosen index position.
	 * <p>
	 * In this version of the implementation (might change in the future) the following properties
	 * and property descriptions are set:<br>
	 * - {@link PID#OBJECT_TYPE} and property description,
	 * representing the interface object type<br>
	 * - {@link PID#OBJECT_NAME} and property description, holding the interface object name<br>
	 * - {@link PID#OBJECT_INDEX} and property description, holding the index of the interface object<br>
	 *
	 * @param objectType Interface Object type, see {@link InterfaceObject} constants
	 * @return the added interface object
	 */
	public InterfaceObject addInterfaceObject(final int objectType)
	{
		final InterfaceObject io;
		final int index;
		synchronized (objects) {
			index = objects.size();
			io = newInterfaceObject(objectType, index, client.getDefinitions());
			objects.add(io);
			updateIoList();
		}
		initIoProperties(io, true);
		if (objectType == InterfaceObject.DEVICE_OBJECT)
			adapter.createNewDescription(0, PID.IO_LIST, false);
		if (io instanceof SecurityObject)
			((SecurityObject) io).populateWithDefaults();
		return io;
	}

	private static InterfaceObject newInterfaceObject(final int objectType, final int index,
			final Map<PropertyKey, Property> definitions) {
		if (objectType == InterfaceObject.DEVICE_OBJECT)
			return new DeviceObject(objectType, index, definitions);
		if (objectType == InterfaceObject.SECURITY_OBJECT)
			return new SecurityObject(objectType, index, definitions);
		return new InterfaceObject(objectType, index, definitions);
	}

	/**
	 * Removes the specified interface object from the list of interface objects maintained by this
	 * Interface Object Server.
	 *
	 * @param io the interface object to remove
	 */
	public void removeInterfaceObject(final InterfaceObject io)
	{
		synchronized (objects) {
			objects.remove(io);
		}
	}

	/**
	 * Adds the specified event listener <code>l</code> to receive events from this interface object
	 * server.
	 * <p>
	 * If <code>l</code> was already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	public void addServerListener(final InterfaceObjectServerListener l)
	{
		listeners.add(l);
	}

	/**
	 * Removes the specified event listener <code>l</code>, so it does no longer receive events from
	 * this interface object server.
	 * <p>
	 * If <code>l</code> was not added in the first place, no action is performed.
	 *
	 * @param l the listener to remove
	 */
	public void removeServerListener(final InterfaceObjectServerListener l)
	{
		listeners.remove(l);
	}

	@Override
	public byte[] getProperty(final int objectIndex, final int propertyId, final int start,
		final int elements) throws KnxPropertyException
	{
		return adapter.getProperty(objectIndex, propertyId, start, elements);
	}

	/**
	 * {@inheritDoc} The current number of value elements maintained by a property can be reset to 0
	 * elements the following way: invoke for the property in question, with parameters
	 * <code>start = 0</code>, <code>elements = 1</code>, and <code>data = { 0, 0 }</code>. This
	 * removes all value elements of that property, with the current number of elements (as obtained
	 * by {@link #getDescription(int, int)}) becoming 0.
	 */
	@Override
	public void setProperty(final int objectIndex, final int propertyId, final int start,
		final int elements, final byte... data) throws KnxPropertyException
	{
		adapter.setProperty(objectIndex, propertyId, start, elements, data);
	}

	/**
	 * See {@link #setProperty(int, int, int, int, byte[])}, but uses the object type and object
	 * instance to refer to the interface object.
	 *
	 * @param objectType object type of the interface object containing the KNX property
	 * @param objectInstance object instance of the interface object in the server, 1 refers to the
	 *        first instance
	 * @param propertyId see {@link #setProperty(int, int, int, int, byte[])}
	 * @param start see {@link #setProperty(int, int, int, int, byte[])}
	 * @param elements see {@link #setProperty(int, int, int, int, byte[])}
	 * @param data see {@link #setProperty(int, int, int, int, byte[])}
	 * @throws KnxPropertyException see {@link #setProperty(int, int, int, int, byte[])}
	 */
	public void setProperty(final int objectType, final int objectInstance, final int propertyId,
		final int start, final int elements, final byte... data) throws KnxPropertyException
	{
		adapter.setProperty(objectType, objectInstance, propertyId, start, elements, data);
	}

	/**
	 * See {@link #getProperty(int, int, int, int)}, but uses the object type and object instance to
	 * refer to the interface object.
	 *
	 * @param objectType object type of the interface object containing the KNX property
	 * @param objectInstance object instance of the interface object in the server, 1 refers to the
	 *        first instance
	 * @param propertyId see {@link #getProperty(int, int, int, int)}
	 * @param start see {@link #getProperty(int, int, int, int)}
	 * @param elements see {@link #getProperty(int, int, int, int)}
	 * @return see {@link #getProperty(int, int, int, int)}
	 * @throws KnxPropertyException see {@link #getProperty(int, int, int, int)}
	 */
	public byte[] getProperty(final int objectType, final int objectInstance, final int propertyId,
		final int start, final int elements) throws KnxPropertyException
	{
		return adapter.getProperty(objectType, objectInstance, propertyId, start, elements);
	}

	@Override
	public void setProperty(final int objIndex, final int propertyId, final int position,
		final String value) throws KNXException
	{
		try {
			client.setProperty(objIndex, propertyId, position, value);
		}
		catch (final InterruptedException e) {
			throw new IllegalStateException("IOS adapter does not throw InterruptedException", e);
		}
	}

	/**
	 * Gets one or more elements of a property with the returned data set in a DPT translator of the
	 * associated data type.
	 *
	 * @param objIndex interface object index in the device
	 * @param pid property identifier
	 * @param start index of the first array element to get
	 * @param elements number of elements to get in the property
	 * @return a DPT translator containing the returned the element data
	 * @throws KNXException on adapter errors while querying the property element or data type
	 *         translation problems
	 */
	@Override
	public DPTXlator getPropertyTranslated(final int objIndex, final int pid, final int start,
		final int elements) throws KNXException
	{
		try {
			return client.getPropertyTranslated(objIndex, pid, start, elements);
		}
		catch (final InterruptedException e) {
			throw new IllegalStateException("IOS adapter does not throw InterruptedException", e);
		}
	}

	/**
	 * Sets the property description for a KNX property.
	 * <p>
	 * The property description is set to describe the property contained in the interface object
	 * referred to by <code>d.getObjectIndex()</code>. If the object index refers to a global
	 * property, the description describes a KNX property allowed in any interface object. An
	 * already existing property description for that property is replaced by <code>d</code>. Actual
	 * property values for the property described do not have to exist yet.
	 * <p>
	 * The interface object server checks the description against the referred interface object to
	 * ensure a valid property description. If the caller allows corrections to the description,
	 * differing description entries are adjusted so they match (e.g., the object type). If no
	 * corrections are allowed, an {@link KNXIllegalArgumentException} is thrown if validation
	 * failed.<br>
	 * A caller can benefit from this behavior and leave the object type, property index, current
	 * elements, and property data type (PDT) empty and let the server fill in those details.
	 *
	 * @param d the KNX property description to set
	 * @param allowCorrections <code>true</code> to allow corrections by the interface object server
	 *        to the description, <code>false</code> otherwise
	 */
	public void setDescription(final Description d, final boolean allowCorrections)
	{
		final InterfaceObject io = getIfObject(d.getObjectIndex());
		io.setDescription(d, allowCorrections);
	}

	@Override
	public Description getDescription(final int objIndex, final int pid) throws KnxPropertyException
	{
		try {
			return client.getDescription(objIndex, pid);
		}
		catch (final KNXException e) {
			// KNXException is currently thrown by PropertyClient.getObjectType,
			// quite unnecessary to use that base type exception (maybe rework).
			final KnxPropertyException pe = new KnxPropertyException(e.getMessage());
			pe.setStackTrace(e.getStackTrace());
			throw pe;
		}
		catch (final InterruptedException e) {
			throw new IllegalStateException("IOS adapter does not throw InterruptedException", e);
		}
	}

	@Override
	public Description getDescriptionByIndex(final int objIndex, final int propIndex) throws KnxPropertyException
	{
		try {
			return client.getDescriptionByIndex(objIndex, propIndex);
		}
		catch (final KNXException e) {
			// KNXException is currently thrown by PropertyClient.getObjectType,
			// quite unnecessary to use that base type exception (maybe rework).
			final KnxPropertyException pe = new KnxPropertyException(e.getMessage());
			pe.setStackTrace(e.getStackTrace());
			throw pe;
		}
		catch (final InterruptedException e) {
			throw new IllegalStateException("IOS adapter does not throw InterruptedException", e);
		}
	}

	@Override
	public String toString() {
		return objects.toString();
	}

	private void updateIoList()
	{
		final InterfaceObject io = objects.get(0);
		if (io == null || io.getType() != InterfaceObject.DEVICE_OBJECT)
			throw new IllegalStateException("IOS is missing mandatory device object");

		final int items = objects.size();
		final var buffer = ByteBuffer.allocate(2 + items * 2).putShort((short) items);
		for (final var interfaceObject : objects)
			buffer.putShort((short) interfaceObject.getType());

		objects.get(0).values.put(new PropertyKey(InterfaceObject.DEVICE_OBJECT, PID.IO_LIST), buffer.array());
	}

	void initIoProperties(final InterfaceObject io, final boolean createDescription)
	{
		final int objectType = io.getType();
		final int index = io.getIndex();
		// add object type property to the interface object
		io.values.put(new PropertyKey(objectType, PID.OBJECT_TYPE),
				new byte[] { 0, 1, (byte) (objectType >> 8), (byte) objectType });
		if (createDescription)
			adapter.createNewDescription(index, PID.OBJECT_TYPE, false);

		final byte[] name = io.getTypeName().getBytes(Charset.forName("ISO-8859-1"));
		final byte[] value = ByteBuffer.allocate(2 + name.length).put((byte) 0).put((byte) name.length).put(name).array();
		io.values.put(new PropertyKey(objectType, PID.OBJECT_NAME), value);
		if (createDescription)
			adapter.createNewDescription(index, PID.OBJECT_NAME, false);

		io.values.put(new PropertyKey(objectType, PID.OBJECT_INDEX), new byte[] { 0, 1, (byte) index });
		if (createDescription)
			adapter.createNewDescription(index, PID.OBJECT_INDEX, false);
	}

	private void firePropertyChanged(final InterfaceObject io, final int propertyId,
		final int start, final int elements, final byte[] data)
	{
		final PropertyEvent pe = new PropertyEvent(this, io, propertyId, start, elements, data);
		listeners.fire(l -> l.onPropertyValueChanged(pe));
	}

	private InterfaceObject getIfObject(final int objIndex)
	{
		synchronized (objects) {
			for (final Iterator<InterfaceObject> i = objects.iterator(); i.hasNext();) {
				final InterfaceObject io = i.next();
				if (io.getIndex() == objIndex)
					return io;
			}
		}
		throw new KNXIllegalArgumentException("interface object index " + objIndex + " past last interface object");
	}

	// Adapter only throws KnxPropertyException on get/set property/desc
	private final class IosAdapter implements PropertyAdapter
	{
		@Override
		public void setProperty(final int objIndex, final int pid, final int start,
			final int elements, final byte... data) throws KnxPropertyException
		{
			setProperty(getIfObject(objIndex), pid, start, elements, data);
		}

		public void setProperty(final int objectType, final int objectInstance, final int propertyId, final int start,
			final int elements, final byte... data) throws KnxPropertyException
		{
			setProperty(lookup(objectType, objectInstance), propertyId, start, elements, data);
		}

		@Override
		public byte[] getProperty(final int objIndex, final int pid, final int start, final int elements)
			throws KnxPropertyException
		{
			return getProperty(getIfObject(objIndex), pid, start, elements);
		}

		public byte[] getProperty(final int objectType, final int objectInstance, final int propertyId, final int start,
			final int elements) throws KnxPropertyException
		{
			return getProperty(lookup(objectType, objectInstance), propertyId, start, elements);
		}

		@Override
		public byte[] getDescription(final int objIndex, final int pid, final int propIndex) throws KnxPropertyException
		{
			final var io = getIfObject(objIndex);
			return io.getDescription(pid, propIndex);
		}

		@Override
		public String getName()
		{
			return "Calimero IOS adapter";
		}

		@Override
		public boolean isOpen()
		{
			return true;
		}

		@Override
		public void close() {}

		private void setProperty(final InterfaceObject io, final int pid, final int start,
			final int elements, final byte[] data) throws KnxPropertyException
		{
			final boolean changed = io.setProperty(pid, start, elements, data, strictMode);
			if (changed)
				firePropertyChanged(io, pid, start, elements, data);
		}

		private byte[] getProperty(final InterfaceObject io, final int pid, final int start, final int elements)
				throws KnxPropertyException {
			return io.getProperty(pid, start, elements);
		}

		private void createNewDescription(final int objIndex, final int pid, final boolean writeEnabled) {
			final InterfaceObject io = getIfObject(objIndex);
			io.createNewDescription(pid, writeEnabled);
		}
	}

	/**
	 * Interface for serializing and deserializing Interface Object Server (IOS) information.
	 * <p>
	 * This interface provides methods to load and save interface objects, together with the
	 * contained KNX properties. A property item includes the property description, and property
	 * element values.<br>
	 * The resource format used to persist the data is implementation specific.
	 */
	public interface IosResourceHandler
	{
		/**
		 * Reads interface object data from a resource identified by <code>resource</code> , and
		 * creates {@link InterfaceObject}s.
		 * <p>
		 *
		 * @param resource identifies the resource to read from
		 * @return a collection of all loaded interface objects of type {@link InterfaceObject}
		 * @throws KNXException on errors accessing the resource, parsing the data, or creating the
		 *         interface objects
		 */
		Collection<InterfaceObject> loadInterfaceObjects(String resource) throws KNXException;

		/**
		 * Reads interface object data from the supplied input stream, and creates {@link InterfaceObject}s.
		 *
		 * @param is input stream to read from
		 * @return a collection of all loaded interface objects of type {@link InterfaceObject}
		 * @throws KNXException on errors accessing the resource, parsing the data, or creating the
		 *         interface objects
		 */
		Collection<InterfaceObject> loadInterfaceObjects(InputStream is) throws KNXException;

		/**
		 * Saves interface objects to a resource identified by <code>resource</code>.
		 * <p>
		 * All information maintained by an interface object are subject to serialization, this
		 * includes all of its KNX property information.
		 *
		 * @param resource identifies the resource to save to
		 * @param ifObjects a collection of interface objects, type {@link InterfaceObject}, to save
		 * @throws KNXException on errors accessing the resource, or saving the data
		 */
		void saveInterfaceObjects(String resource, Collection<InterfaceObject> ifObjects) throws KNXException;

		/**
		 * Saves interface objects to the supplied output stream.
		 * <p>
		 * All information maintained by an interface object are subject to serialization, this
		 * includes all of its KNX property information.
		 *
		 * @param os output stream to write to
		 * @param ifObjects a collection of interface objects, type {@link InterfaceObject}, to save
		 * @throws KNXException on errors accessing the resource, or saving the data
		 */
		void saveInterfaceObjects(OutputStream os, Collection<InterfaceObject> ifObjects) throws KNXException;

		/**
		 * Reads KNX property data from a resource identified by <code>resource</code>, and loads
		 * description information into objects of type {@link Description} and KNX property element
		 * values as <code>byte[]</code> objects.
		 * <p>
		 * When the method returns, <code>descriptions</code> and <code>values</code> contain the
		 * loaded {@link Description} and <code>byte[]</code> objects, respectively.
		 *
		 * @param resource identifies the resource to read from
		 * @param descriptions a collection with the loaded description objects added to it
		 * @param values a collection with the loaded property element values added to it, of type
		 *        <code>byte[]</code>
		 * @throws KNXException on errors accessing the resource, parsing the data, or object
		 *         creation
		 */
		void loadProperties(String resource, Collection<Description> descriptions,
			Collection<byte[]> values) throws KNXException;

		void loadProperties(Collection<Description> descriptions, Collection<byte[]> values) throws KNXException;

		/**
		 * Saves KNX property information to a resource identified by <code>resource</code>.
		 * <p>
		 * The two collections <code>descriptions</code> and <code>values</code> holding the KNX
		 * property descriptions and property element data are associated by the collection's
		 * iterators {@link Collection#iterator()}: the n<sup>th</sup> description element returned
		 * by the <code>descriptions</code> iterator corresponds to the n<sup>th</sup> value element
		 * returned by the <code>values</code> iterator.
		 *
		 * @param resource identifies the resource to save to
		 * @param descriptions a collection of property descriptions, of type {@link Description}
		 * @param values a collection of property value data, of type <code>byte[]</code>; every
		 *        <code>values</code> entry corresponds to one <code>descriptions</code> entry,
		 *        aligned by the {@link Iterator#next()} behavior of the supplied collections
		 * @throws KNXException on errors accessing the resource, or saving the data
		 */
		void saveProperties(String resource, Collection<Description> descriptions,
			Collection<byte[]> values) throws KNXException;

		void saveProperties(Collection<Description> descriptions, Collection<byte[]> values) throws KNXException;
	}

	private static class XmlSerializer implements IosResourceHandler
	{
		private static final String TAG_IOS = "interfaceObjects";

		private static final String TAG_OBJECT = "object";
		private static final String ATTR_OBJECTTYPE = "type";

		private static final String TAG_PROPERTY = "property";
		private static final String ATTR_PID = "pid";
		private static final String ATTR_INDEX = "index";
		private static final String ATTR_PDT = "pdt";
		private static final String ATTR_RW = "rw";
		private static final String ATTR_WRITE = "writeEnabled";
		private static final String ATTR_MAXELEMS = "maxElements";

		private static final String TAG_DATA = "data";

		private XmlReader r;
		private XmlWriter w;

		private final Logger logger;
		private final Map<PropertyKey, Property> definitions;

		XmlSerializer(final Logger l, final Map<PropertyKey, Property> definitions)
		{
			logger = l;
			this.definitions = definitions;
		}

		@Override
		public Collection<InterfaceObject> loadInterfaceObjects(final String resource) throws KNXException {
			try (var reader = XmlInputFactory.newInstance().createXMLReader(resource)) {
				return load(reader);
			}
			catch (final NumberFormatException e) {
				throw new KNXFormatException("loading interface objects", e.getMessage());
			}
		}

		@Override
		public Collection<InterfaceObject> loadInterfaceObjects(final InputStream is) throws KNXException {
			try (var reader = XmlInputFactory.newInstance().createXMLStreamReader(is)) {
				return load(reader);
			}
			catch (final NumberFormatException e) {
				throw new KNXFormatException("loading interface objects", e.getMessage());
			}
		}

		private Collection<InterfaceObject> load(final XmlReader reader) throws KNXException {
			r = reader;
			if (reader.nextTag() != XmlReader.START_ELEMENT || !r.getLocalName().equals(TAG_IOS))
				throw new KNXMLException("no interface objects");
			final List<InterfaceObject> list = new ArrayList<>();
			while (r.next() != XmlReader.END_DOCUMENT) {
				if (r.getEventType() == XmlReader.START_ELEMENT) {
					if (r.getLocalName().equals(TAG_OBJECT)) {
						// on no type attribute, toInt() throws, that's ok
						final int type = toInt(r.getAttributeValue(null, ATTR_OBJECTTYPE));
						final int index = toInt(r.getAttributeValue(null, ATTR_INDEX));
						final InterfaceObject io = newInterfaceObject(type, index, definitions);
						list.add(io);
						io.load(this);
					}
				}
				else if (r.getEventType() == XmlReader.END_ELEMENT
						&& r.getLocalName().equals(TAG_IOS))
					break;
			}
			return list;
		}

		@Override
		public void saveInterfaceObjects(final String resource, final Collection<InterfaceObject> objects)
				throws KNXException {
			try (var writer = XmlOutputFactory.newInstance().createXMLWriter(resource)) {
				save(objects, writer);
			}
		}

		@Override
		public void saveInterfaceObjects(final OutputStream os, final Collection<InterfaceObject> ifObjects)
				throws KNXException {
			try (var writer = XmlOutputFactory.newInstance().createXMLStreamWriter(os)) {
				save(ifObjects, writer);
			}
		}

		private void save(final Collection<InterfaceObject> objects, final XmlWriter writer) throws KNXException {
			w = writer;
			writer.writeStartDocument("UTF-8", "1.0");
			w.writeComment("Calimero v" + Settings.getLibraryVersion() + " interface objects, saved on "
					+ ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME));
			w.writeStartElement(TAG_IOS);
			for (final var io : objects) {
				w.writeStartElement(TAG_OBJECT);
				w.writeAttribute(ATTR_OBJECTTYPE, Integer.toString(io.getType()));
				w.writeAttribute(ATTR_INDEX, Integer.toString(io.getIndex()));
				io.save(this);
				w.writeEndElement();
			}
			w.writeEndDocument();
		}

		@Override
		public void loadProperties(final String resource, final Collection<Description> descriptions,
				final Collection<byte[]> values) throws KNXException {
			loadProperties(descriptions, values);
		}

		@Override
		public void loadProperties(final Collection<Description> descriptions, final Collection<byte[]> values)
				throws KNXException {
			try {
				int type = 0;
				int oi = 0;
				if (r.getLocalName().equals(TAG_OBJECT)) {
					type = toInt(r.getAttributeValue(null, ATTR_OBJECTTYPE));
					oi = toInt(r.getAttributeValue(null, ATTR_INDEX));
				}
				// For every added property description, one property element value is
				// required; this toggle bit makes sure we keep aligned in case a xml
				// property element does not contain a data element. And since we are
				// not validating the xml schema, this should be enough.
				boolean valueExpected = false;

				int index = 0;
				Description currentDesc = null;
				while (r.next() != XmlReader.END_DOCUMENT) {
					if (r.getEventType() == XmlReader.START_ELEMENT) {
						if (r.getLocalName().equals(TAG_PROPERTY)) {
							final int maxElems = toInt(r.getAttributeValue(null, ATTR_MAXELEMS));
							final int[] rw = parseRW(r.getAttributeValue(null, ATTR_RW));
							final Description d = new Description(oi, type,
									toInt(r.getAttributeValue(null, ATTR_PID)), index,
									toInt(r.getAttributeValue(null, ATTR_PDT)),
									toInt(r.getAttributeValue(null, ATTR_WRITE)) == 1, 0,
									maxElems, rw[0], rw[1]);
							descriptions.add(d);
							index++;
							if (valueExpected) {
								values.add(new byte[2]);
								logger.trace("{}: 0000", currentDesc);
							}
							valueExpected = true;
							currentDesc = d;
						}
						else if (r.getLocalName().equals(TAG_DATA)) {
							String s = r.getElementText();
							if (s.length() % 2 == 1)
								s = "0" + s;
							logger.trace("{}: {}", currentDesc, s);
							final byte[] data = DataUnitBuilder.fromHex(s);
							values.add(data.length == 0 ? new byte[2] : data);
							valueExpected = false;
						}
					}
					else if (r.getEventType() == XmlReader.END_ELEMENT && r.getLocalName().equals(TAG_OBJECT))
						break;
				}
			}
			catch (final NumberFormatException e) {
				throw new KNXFormatException("loading properties", e.getMessage());
			}
		}

		@Override
		public void saveProperties(final String resource, final Collection<Description> descriptions,
				final Collection<byte[]> values) {
			saveProperties(descriptions, values);
		}

		@Override
		public void saveProperties(final Collection<Description> descriptions, final Collection<byte[]> values) {
			if (values.size() < descriptions.size())
				throw new KNXIllegalArgumentException("values size " + values.size()
						+ " less than descriptions size " + descriptions.size());
			final Iterator<byte[]> k = values.iterator();
			for (final var d : descriptions) {
				final byte[] data = k.next();
				w.writeStartElement(TAG_PROPERTY);
				w.writeAttribute(ATTR_PID, Integer.toString(d.getPID()));
				w.writeAttribute(ATTR_PDT, d.getPDT() == -1 ? "<tbd>" : Integer.toString(d.getPDT()));
				w.writeAttribute(ATTR_MAXELEMS, Integer.toString(d.getMaxElements()));
				w.writeAttribute(ATTR_RW, Integer.toString(d.getReadLevel()) + "/" + d.getWriteLevel());
				w.writeAttribute(ATTR_WRITE, d.isWriteEnabled() ? "1" : "0");
				writeData(data);
				w.writeEndElement();
			}
			while (k.hasNext()) {
				final byte[] data = k.next();
				w.writeStartElement(TAG_PROPERTY);
				writeData(data);
				w.writeEndElement();
			}
		}

		private void writeData(final byte[] data) {
			if (data.length == 0)
				w.writeEmptyElement(TAG_DATA);
			else {
				w.writeStartElement(TAG_DATA);
				w.writeCharacters(DataUnitBuilder.toHex(data, ""));
				w.writeEndElement();
			}
		}

		private static int[] parseRW(final String rw)
		{
			final String s = rw.toLowerCase();
			int read = 0;
			int write = 0;
			boolean slash = false;
			for (int i = 0; i < s.length(); i++) {
				final char c = s.charAt(i);
				if (c == '/')
					slash = true;
				else if (c >= '0' && c <= '9')
					if (slash)
						write = write * 10 + c - '0';
					else
						read = read * 10 + c - '0';
			}
			return new int[] { read, write };
		}

		private static int toInt(final String s) throws NumberFormatException
		{
			if (s != null) {
				if (s.equals("<tbd>"))
					return -1;
				return s.length() == 0 ? 0 : Integer.decode(s).intValue();
			}
			throw new NumberFormatException("no integer number: " + s);
		}
	}
}
