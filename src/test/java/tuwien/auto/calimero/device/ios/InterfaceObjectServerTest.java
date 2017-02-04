/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2017 B. Malinowsky

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Collection;
import java.util.Iterator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer.IosResourceHandler;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XmlReader;
import tuwien.auto.calimero.xml.XmlWriter;

/**
 * @author B. Malinowsky
 */
public class InterfaceObjectServerTest
{
	private static final String baseDir = "src/test/resources/";
	private static final String propertiesFile = baseDir + "properties.xml";

	private InterfaceObjectServer ios;

	@BeforeEach
	void init() throws Exception
	{
		ios = new InterfaceObjectServer(false);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#InterfaceObjectServer(boolean)} .
	 *
	 * @throws KNXException
	 */
	@Test
	void interfaceObjectServer() throws KNXException
	{
		new InterfaceObjectServer(false);
		new InterfaceObjectServer(true);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#setResourceHandler(InterfaceObjectServer.IosResourceHandler)}.
	 */
	@Test
	void setResourceHandler()
	{
		ios.setResourceHandler(null);
		ios.setResourceHandler(new IosResourceHandler() {
			public void save(final String resource, final Collection<Property> definitions) throws KNXMLException
			{}

			@Override
			public void save(final XmlWriter writer, final Collection<Property> definitions) throws KNXMLException
			{}

			public Collection<Property> load(final String resource) throws KNXMLException
			{
				return null;
			}

			@Override
			public Collection<Property> load(final XmlReader reader) throws KNXMLException
			{
				return null;
			}

			public void saveProperties(final String resource, final Collection<Description> descriptions,
				final Collection<byte[]> values) throws KNXException
			{}

			public void saveInterfaceObjects(final String resource, final Collection<InterfaceObject> ifObjects)
				throws KNXException
			{}

			public void loadProperties(final String resource, final Collection<Description> descriptions,
				final Collection<byte[]> values) throws KNXException
			{}

			public Collection<InterfaceObject> loadInterfaceObjects(final String resource) throws KNXException
			{
				return null;
			}
		});
	}

	/**
	 * Test method for {@link InterfaceObjectServer#loadDefinitions(java.lang.String)}.
	 *
	 * @throws KNXException
	 */
	@Test
	void loadDefinitions() throws KNXException
	{
		ios.loadDefinitions(propertiesFile);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#loadInterfaceObjects(java.lang.String)} .
	 *
	 * @throws KNXException
	 */
	@Test
	void loadInterfaceObjects() throws KNXException
	{
		ios.loadInterfaceObjects(baseDir + "testLoadInterfaceObjects.xml");
		final Description d = ios.getDescription(0, 1);
		final InterfaceObject[] objects = ios.getInterfaceObjects();
		assertNotNull(objects);
		assertTrue(objects.length > 2);
		for (int i = 0; i < objects.length; i++) {
			final InterfaceObject interfaceObject = objects[i];
			assertEquals(i, interfaceObject.getIndex());
			for (final Iterator<PropertyKey> k = interfaceObject.values.keySet().iterator(); k.hasNext();) {
				final PropertyKey key = k.next();
				assertNotNull(key);
				assertNotNull(interfaceObject.values.get(key));
			}
		}
		assertEquals(0, d.getPDT());
	}

	/**
	 * Test method for {@link InterfaceObjectServer#saveInterfaceObjects(java.lang.String)}.
	 *
	 * @throws KNXException
	 */
	@Test
	void SaveInterfaceObjects() throws KNXException
	{
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, 4, new byte[] { 1, 1, 2, 2, 3, 3, 4, 4 });
		ios.saveInterfaceObjects(baseDir + "testSaveInterfaceObjects.xml");
	}

	/**
	 * Test method for {@link InterfaceObjectServer#getInterfaceObjects()}.
	 */
	@Test
	void getInterfaceObjects()
	{
		final InterfaceObject[] objects = ios.getInterfaceObjects();
		assertNotNull(objects);
		assertEquals(2, objects.length);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#addInterfaceObject(int)}.
	 */
	@Test
	void addInterfaceObject()
	{
		final int length = ios.getInterfaceObjects().length;
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		assertEquals(length + 1, ios.getInterfaceObjects().length);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#addServerListener(InterfaceObjectServerListener)}.
	 */
	@Test
	void addServerListener()
	{
		ios.addServerListener(e -> {});
	}

	/**
	 * Test method for {@link InterfaceObjectServer#removeServerListener(InterfaceObjectServerListener)}.
	 */
	@Test
	void removeServerListener()
	{
		final InterfaceObjectServerListener l = e -> {};
		ios.removeServerListener(l);
		ios.addServerListener(l);
		ios.removeServerListener(l);
		ios.removeServerListener(l);
	}

	private final int objectType = InterfaceObject.DEVICE_OBJECT;
	private final int objectIndex = 0;
	private final int objectInstance = 1;
	private final int propertyId = PID.OBJECT_INDEX;

	/**
	 * Test method for {@link InterfaceObjectServer#getProperty(int, int, int, int)} .
	 *
	 * @throws KnxPropertyException
	 */
	@Test
	void getPropertyIntIntIntInt() throws KnxPropertyException
	{
		ios.getProperty(objectIndex , propertyId, 1, 1);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#setProperty(int, int, int, int, byte[])} .
	 *
	 * @throws KnxPropertyException
	 */
	@Test
	void setPropertyIntIntIntIntByteArray() throws KnxPropertyException
	{
		ios.setProperty(objectIndex, propertyId, 1, 1, new byte[] { 0, 0});
	}

	/**
	 * Test method for {@link InterfaceObjectServer#setProperty(int, int, int, int, int, byte[])}.
	 *
	 * @throws KnxPropertyException
	 */
	@Test
	void setPropertyIntIntIntIntIntByteArray() throws KnxPropertyException
	{
		ios.setProperty(objectType, objectInstance, propertyId, 1, 1, new byte[] { 0, 0 });
	}

	/**
	 * Test method for {@link InterfaceObjectServer#getProperty(int, int, int, int, int)} .
	 * @throws KnxPropertyException
	 */
	@Test
	void getPropertyIntIntIntIntInt() throws KnxPropertyException
	{
		ios.getProperty(objectType, objectInstance , propertyId, 1, 1);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#setProperty(int, int, int, java.lang.String)}.
	 */
	@Test
	void setPropertyIntIntIntString()
	{
	}

	/**
	 * Test method for {@link InterfaceObjectServer#getPropertyTranslated(int, int, int, int)}.
	 */
	@Test void GetPropertyTranslated()
	{
	}

	/**
	 * Test method for {@link InterfaceObjectServer#setDescription(tuwien.auto.calimero.mgmt.Description, boolean)}.
	 */
	@Test
	void setDescription()
	{
		final Description set = new Description(0, 0, 1, 0, 15, false, 1, 1, 3, 3);
		ios.setDescription(set, true);
	}

	/**
	 * Test method for {@link InterfaceObjectServer#getDescription(int, int)}.
	 * @throws KnxPropertyException
	 */
	@Test
	void getDescription() throws KnxPropertyException
	{
		final Description d = ios.getDescription(0, 1);
		assertNotNull(d);
	}

	@Test
	void resetElements() throws KNXException
	{
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		// get KNXnet/IP parameter object to set some additional addresses
		final InterfaceObject[] objs = ios.getInterfaceObjects();
		int objIdx = -1;
		for (int i = 0; i < objs.length; i++) {
			final InterfaceObject io = objs[i];
			if (io.getType() == InterfaceObject.KNXNETIP_PARAMETER_OBJECT) {
				objIdx = i;
				break;
			}
		}
		ios.setDescription(
				new Description(objIdx, 0, PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 0, true, 0, 20, 3, 3),
				true);
		Description d = ios.getDescription(objIdx, PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		assertTrue(d.getCurrentElements() == 0);

		// set addresses
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, 3, new byte[] { 1, 1, 1, 2, 1, 3 });
		d = ios.getDescription(objIdx, PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		assertTrue(d.getCurrentElements() == 3);

		// try not allowed ways to access current number of elements

		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 2, new byte[] { 0, 0, });
			fail("only one element allowed");
		}
		catch (final KnxPropertyException e) {
			// ok
		}

		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1, new byte[] { 1, 0, });
			fail("only 0 value allowed");
		}
		catch (final KnxPropertyException e) {
			// ok
		}

		try {
			ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
					PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1, new byte[] { 0, 0, 0, });
			fail("only byte array length 2 allowed");
		}
		catch (final KnxPropertyException e) {
			// ok
		}

		// try correct way to reset current number of elements
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 0, 1, new byte[] { 0, 0, });
		d = ios.getDescription(objIdx, PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
		assertTrue(d.getCurrentElements() == 0);
	}
}
