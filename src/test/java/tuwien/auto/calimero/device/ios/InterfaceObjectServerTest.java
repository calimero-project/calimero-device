/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2020 B. Malinowsky

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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Collection;
import java.util.Iterator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer.IosResourceHandler;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;

class InterfaceObjectServerTest
{
	private static final String baseDir = "src/test/resources/";
	private static final String propertiesFile = "/properties.xml";

	private InterfaceObjectServer ios;

	@BeforeEach
	void init() throws Exception
	{
		ios = new InterfaceObjectServer(false);
	}

	@Test
	void interfaceObjectServer() throws KNXException
	{
		new InterfaceObjectServer(false);
		new InterfaceObjectServer(true);
	}

	@Test
	void setResourceHandler()
	{
		ios.setResourceHandler(null);
		ios.setResourceHandler(new IosResourceHandler() {
			@Override
			public void saveProperties(final String resource, final Collection<Description> descriptions,
				final Collection<byte[]> values) throws KNXException
			{}

			@Override
			public void saveProperties(final Collection<Description> descriptions, final Collection<byte[]> values)
					throws KNXException {
			}

			@Override
			public void saveInterfaceObjects(final String resource, final Collection<InterfaceObject> ifObjects)
				throws KNXException
			{}

			@Override
			public void saveInterfaceObjects(final OutputStream os, final Collection<InterfaceObject> ifObjects)
					throws KNXException {
			}

			@Override
			public void loadProperties(final String resource, final Collection<Description> descriptions,
				final Collection<byte[]> values) throws KNXException
			{}

			@Override
			public void loadProperties(final Collection<Description> descriptions, final Collection<byte[]> values)
				throws KNXException {
			}

			@Override
			public Collection<InterfaceObject> loadInterfaceObjects(final String resource) throws KNXException
			{
				return null;
			}

			@Override
			public Collection<InterfaceObject> loadInterfaceObjects(final InputStream is) throws KNXException {
				return null;
			}
		});
	}

	@Test
	void loadDefinitions() throws KNXException
	{
		final URL resource = getClass().getResource(propertiesFile);
		ios.loadDefinitions(resource.toString());
	}

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
		assertEquals(4, d.getPDT());
	}

	@Test
	void saveInterfaceObjects() throws KNXException
	{
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
				PropertyAccess.PID.ADDITIONAL_INDIVIDUAL_ADDRESSES, 1, 4, new byte[] { 1, 1, 2, 2, 3, 3, 4, 4 });
		ios.saveInterfaceObjects(baseDir + "testSaveInterfaceObjects.xml");
	}

	@Test
	void getInterfaceObjects()
	{
		final InterfaceObject[] objects = ios.getInterfaceObjects();
		assertNotNull(objects);
		assertEquals(1, objects.length);
	}

	@Test
	void addInterfaceObject()
	{
		final int length = ios.getInterfaceObjects().length;
		ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		assertEquals(length + 1, ios.getInterfaceObjects().length);
	}

	@Test
	void addServerListener()
	{
		ios.addServerListener(e -> {});
	}

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

	@Test
	void getPropertyIntIntIntInt() throws KnxPropertyException
	{
		ios.getProperty(objectIndex, propertyId, 1, 1);
	}

	@Test
	void setPropertyIntIntIntIntByteArray() throws KnxPropertyException
	{
		ios.setProperty(objectIndex, propertyId, 1, 1, new byte[] { 0 });
	}

	@Test
	void setPropertyIntIntIntIntIntByteArray() throws KnxPropertyException
	{
		ios.setProperty(objectType, objectInstance, propertyId, 1, 1, new byte[] { 0 });
	}

	@Test
	void getPropertyIntIntIntIntInt() throws KnxPropertyException
	{
		ios.getProperty(objectType, objectInstance, propertyId, 1, 1);
	}

	@Test
	void setDescription()
	{
		final Description set = new Description(0, 0, 1, 0, 15, false, 1, 1, 3, 3);
		ios.setDescription(set, true);
	}

	@Test
	void getDescription() throws KnxPropertyException
	{
		final Description d = ios.getDescription(0, 1);
		assertNotNull(d);
	}

	@Test
	void resetElements() throws KNXException
	{
		final var io = ios.addInterfaceObject(InterfaceObject.KNXNETIP_PARAMETER_OBJECT);
		final int objIdx = io.getIndex();

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
