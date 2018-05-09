/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2018 B. Malinowsky

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

package tuwien.auto.calimero.device;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.link.AbstractLink;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.TPSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.TransportLayer;
import tuwien.auto.calimero.mgmt.TransportLayerImpl;

/**
 * @author B. Malinowsky
 */
public class ManagementServiceTest
{
	private static final int objectIndex = 0;
	private static final int propertyId = PID.OBJECT_TYPE;

	private KnxDeviceServiceLogic mgmt;
	private BaseKnxDevice device;
	private TransportLayer tl;
	private Destination dst;

	private static final byte[] authKey = new byte[] { 0x10, 0x20, 0x30, 0x40 };
	private static final byte[] defaultAuthKey = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

	@BeforeEach
	void init() throws Exception
	{
		final KNXNetworkLink link = new AbstractLink<AutoCloseable>("test link", TPSettings.TP1) {
			@Override
			protected void onSend(final CEMILData msg, final boolean waitForCon) {}

			@Override
			protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon) {}
		};

		mgmt = new KnxDeviceServiceLogic() {
			@Override
			public void updateDatapointValue(final Datapoint ofDp, final DPTXlator update)
			{
				fail("not under test");
			}

			@Override
			public DPTXlator requestDatapointValue(final Datapoint ofDp) throws KNXException
			{
				fail("not under test");
				return null;
			}
		};

		device = new BaseKnxDevice("test", DeviceDescriptor.DD0.TYPE_5705, new IndividualAddress(0, 0x02, 0xff), link, null, mgmt);
		mgmt.setDevice(device);
		mgmt.authKeys[3] = authKey;
		mgmt.minAccessLevel = 15;

		tl = new TransportLayerImpl(link);
		dst = tl.createDestination(new IndividualAddress(1), true);
		tl.connect(dst);
	}

	@AfterEach
	void cleanup() throws KNXLinkClosedException {
		device.setDeviceLink(null);
	}

	@Test
	void readProperty()
	{
		mgmt.authorize(dst, authKey);
		final ServiceResult r = mgmt.readProperty(dst, objectIndex, propertyId, 1, 1);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(2, r.getResult().length);
	}

	@Test
	void writeProperty()
	{
		mgmt.authorize(dst, authKey);
		final byte[] data = new byte[] { 1, 2, 3, 4 };
		ServiceResult r = mgmt.writeProperty(dst, objectIndex, 110, 1, 1, data);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertArrayEquals(data, r.getResult());

		r = mgmt.readProperty(dst, objectIndex, 110, 1, 1);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertArrayEquals(data, r.getResult());
	}

	@Test
	void tryWriteReadOnlyProperty()
	{
		mgmt.authorize(dst, authKey);
		ServiceResult r = mgmt.readProperty(dst, objectIndex, propertyId, 1, 1);
		byte[] data = r.getResult();
		assertNull(mgmt.writeProperty(null, objectIndex, propertyId, 1, 1, data));

		r = mgmt.readProperty(dst, 1, propertyId, 1, 1);
		data = r.getResult();
		assertNull(mgmt.writeProperty(dst, 1, propertyId, 1, 1, data));
	}

	@Test
	void readPropertyDescription()
	{
		ServiceResult r = mgmt.readPropertyDescription(objectIndex, propertyId, 0);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(7, r.getResult().length);
		new Description(0, r.getResult());

		r = mgmt.readPropertyDescription(objectIndex, 0, 0);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(7, r.getResult().length);
		new Description(0, r.getResult());
	}

	@Test
	void readMemory()
	{
		final ServiceResult r = mgmt.readMemory(0x60, 1);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(1, r.getResult().length);
		assertEquals(0, r.getResult()[0]);
	}

	@Test
	void writeMemory()
	{
		final int start = 0x22;
		final byte[] data = new byte[] { 1, 2, 3, 4 };

		ServiceResult r = mgmt.writeMemory(start, data);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(4, r.getResult().length);

		r = mgmt.readMemory(start, 4);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertArrayEquals(data, r.getResult());
	}

	@Test
	void readDescriptor()
	{
		ServiceResult r = mgmt.readDescriptor(0);
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(2, r.getResult().length);
		r = mgmt.readDescriptor(2);
		assertNull(r);
	}

	@Test
	void authorizeInvalidKey()
	{
		assertAuthResult(mgmt.authorize(dst, new byte[] { 3, 3, 3, 3 }), 0xf);
	}

	@Test
	void authorizeFreeAccess()
	{
		assertAuthResult(mgmt.authorize(dst, defaultAuthKey), 0xf);
	}

	@Test
	void modifyAuthKey()
	{
		assertAuthResult(mgmt.authorize(dst, authKey), 3);
		assertAuthResult(mgmt.writeAuthKey(dst, 4, new byte[] { 4, 4, 4, 4 }), 4);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 4, 4, 4, 4 }), 4);
	}

	@Test
	void modifyAuthKeyForCurrentAccessLevel()
	{
		assertAuthResult(mgmt.authorize(dst, authKey), 3);
		assertAuthResult(mgmt.writeAuthKey(dst, 3, new byte[] { 4, 4, 4, 4 }), 3);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 4, 4, 4, 4 }), 3);
	}

	@Test
	void resetAuthKey()
	{
		mgmt.authorize(dst, authKey);
		assertAuthResult(mgmt.writeAuthKey(dst, 4, new byte[] { 4, 4, 4, 4 }), 4);
		assertAuthResult(mgmt.writeAuthKey(dst, 4, defaultAuthKey), 4);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 4, 4, 4, 4 }), 0xf);
	}

	@Test
	void writeAuthKeyWithoutAuthorization()
	{
		assertAuthResult(mgmt.writeAuthKey(dst, 5, new byte[] { 5, 5, 5, 5 }), 0xff);
		assertAuthResult(mgmt.authorize(dst, new byte[] { 5, 5, 5, 5 }), 0xf);
	}

	private void assertAuthResult(final ServiceResult r, final int level)
	{
		assertNotNull(r);
		assertNotNull(r.getResult());
		assertEquals(1, r.getResult().length);
		assertEquals(level, r.getResult()[0] & 0xff);
	}
}
