/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2012, 2015 B. Malinowsky

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

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointMap;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.process.ProcessEvent;

/**
 * Provides the default application layer service logic of a KNX device, without assuming any
 * specific device implementation or restrictions of KNX communication medium.
 *
 * @author B. Malinowsky
 */
public abstract class KnxDeviceServiceLogic implements ProcessCommunicationService, ManagementService
{
	private KnxDevice device;
	private Logger logger;

	// XXX memory operations are not thread-safe
	private static final int MEMORY_SIZE = 5000;
	private byte[] memory;

	private final DatapointModel<Datapoint> datapoints = new DatapointMap<>();

	// domain can be 2 or 6 bytes, set in setDevice()
	private byte[] domainAddress;

	private static final int T_MEDIUM_TP1 = 20; // ms
	private static final int T_MEDIUM_PL110 = 390; // ms
	private int mediumTimeFactor; // [ms]

	// device descriptor type 0
	private final DeviceDescriptor dd;

	public KnxDeviceServiceLogic()
	{
		this(DeviceDescriptor.DD0.TYPE_5705);
	}

	public KnxDeviceServiceLogic(final DeviceDescriptor dd)
	{
		this.dd = dd;
	}

	public void setDevice(final KnxDevice device)
	{
		this.device = device;
		logger = (device instanceof BaseKnxDevice) ? ((BaseKnxDevice) device).getLogger()
				: LoggerFactory.getLogger(KnxDeviceServiceLogic.class);

		domainAddress = new byte[0];
		final int medium = device.getDeviceLink().getKNXMedium().getMedium();
		if (medium == KNXMediumSettings.MEDIUM_PL110) {
			domainAddress = new byte[2];
			mediumTimeFactor = T_MEDIUM_PL110;
		}
		else if (medium == KNXMediumSettings.MEDIUM_RF)
			domainAddress = new byte[6];
		else if (medium == KNXMediumSettings.MEDIUM_TP1)
			mediumTimeFactor = T_MEDIUM_TP1;
	}

	/**
	 * @return the configured datapoints
	 */
	public final DatapointModel<Datapoint> getDatapointModel()
	{
		return datapoints;
	}

	public abstract void updateDatapointValue(final Datapoint ofDp, final DPTXlator update);
//	{
//		state.put(ofDp.getMainAddress(), update.getValue());
//		logger.warn("value update of datapoint {} to {}, but value is not stored",
//				ofDp.getMainAddress(), update.getValue());
//	}

	/**
	 * This default implementation creates the DPT translator for the requested datapoint without
	 * modifying any translator data; override this method to set the requested datapoint value. A
	 * subtype might implement this method as follows:
	 *
	 * <pre>
	 * {@code
	 * try {
	 * 	final DPTXlator t = super.requestDatapointValue(dp);
	 * 	// set the data or value, e.g.:
	 * 	t.setValue( ... provide your datapoint value );
	 * } catch (KNXException e) {
	 * 	// you might want to handle the case when no DPT translator available for this datapoint
	 * }}
	 * </pre>
	 *
	 * @param ofDp the datapoint whose value is requested
	 * @return the created DPT translator for the requested datapoint
	 * @throws KNXException
	 */
	// ??? maybe also make abstract so that users don't forget to implement it
	public DPTXlator requestDatapointValue(final Datapoint ofDp) throws KNXException
	{
		final DPTXlator t = TranslatorTypes.createTranslator(0, ofDp.getDPT());
//		t.setValue(state.get(dp.getMainAddress()));
//		logger.warn("value request for datapoint {}, but no value provided", dp.getMainAddress());
		return t;
	}

	/**
	 * Returns the device memory this KNX device should use for any memory-related operations, e.g.,
	 * memory read/write management service.
	 *
	 * @return the device memory
	 */
	public byte[] getDeviceMemory()
	{
		if (memory == null)
			memory = new byte[MEMORY_SIZE];
		return memory;
	}

	/**
	 * @param inProgrammingMode <code>true</code> if device should be set into programming mode,
	 *        <code>false</code> if programming mode should be switched off (if currently set)
	 */
	public final void setProgrammingMode(final boolean inProgrammingMode)
	{
		final byte[] mem = getDeviceMemory();
		int b = mem[0x60];
		b = inProgrammingMode ? b | 0x01 : b & (~0x01);
		mem[0x60] = (byte) b;
	}

	/**
	 * @return whether the device is in programming mode (<code>true</code>) or not (
	 *         <code>false</code>)
	 */
	public final boolean inProgrammingMode()
	{
		final byte[] mem = getDeviceMemory();
		// check bit 0 at location 0x60 for programming mode
		return (mem[0x60] & 0x01) == 0x01;
	}

	@Override
	public ServiceResult groupReadRequest(final ProcessEvent e)
	{
		final GroupAddress dst = e.getDestination();
		final Datapoint dp = getDatapointModel().get(dst);
		if (dp != null) {
			try {
				final DPTXlator t = requestDatapointValue(dp);
				return new ServiceResult(t.getData(), t.getTypeSize() == 0);
			}
			catch (final KNXException ke) {
				ke.printStackTrace();
				return null;
			}
		}
		return null;
	}

	@Override
	public void groupWrite(final ProcessEvent e)
	{
		final GroupAddress dst = e.getDestination();
		final Datapoint dp = getDatapointModel().get(dst);
		if (dp == null)
			return;
		try {
			final DPTXlator t = TranslatorTypes.createTranslator(0, dp.getDPT());
			t.setData(e.getASDU());
			updateDatapointValue(dp, t);
		}
		catch (final KNXException ex) {
			ex.printStackTrace();
		}
		catch (final KNXIllegalArgumentException iae) {
			iae.printStackTrace();
		}
	}

	@Override
	public void groupResponse(final ProcessEvent e)
	{}

	@Override
	public ServiceResult readProperty(final int objectIndex, final int propertyId,
		final int startIndex, final int elements)
	{
		try {
			final byte[] res = device.getInterfaceObjectServer().getProperty(objectIndex,
					propertyId, startIndex, elements);
			return new ServiceResult(res);
		}
		catch (final KNXPropertyException | KNXIllegalArgumentException e) {
			logger.error("read property " + e);
		}
		return null;
	}

	@Override
	public ServiceResult writeProperty(final int objectIndex, final int propertyId,
		final int startIndex, final int elements, final byte[] data)
	{
		try {
			device.getInterfaceObjectServer().setProperty(objectIndex, propertyId, startIndex,
					elements, data);
			// handle some special cases
			if (propertyId == PID.PROGMODE)
				setProgrammingMode((data[0] & 0x01) == 0x01);

			// TODO on error we return 0 elements and no data, otherwise we return the
			// written elements, as in a property read response
			// but this is crap to do here, the service notifier should do this
			return new ServiceResult(data);
		}
		catch (final KNXPropertyException | KNXIllegalArgumentException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public ServiceResult readPropertyDescription(final int objectIndex, final int propertyId,
		final int propertyIndex)
	{
		try {
			final InterfaceObjectServer ios = device.getInterfaceObjectServer();
			final Description d;
			if (propertyId > 0)
				d = ios.getDescription(objectIndex, propertyId);
			else
				d = ios.getDescriptionByIndex(objectIndex, propertyIndex);
			return new ServiceResult(d.toByteArray());
		}
		catch (final KNXPropertyException e) {
			logger.warn("read property description: " + e.getMessage());
		}
		catch (final KNXIllegalArgumentException e) {
			logger.warn("read property description: " + e.getMessage());
		}
		return null;
	}

	@Override
	public ServiceResult readMemory(final int startAddress, final int bytes)
	{
		return new ServiceResult(DataUnitBuilder.copyOfRange(getDeviceMemory(), startAddress,
				startAddress + bytes));
	}

	@Override
	public ServiceResult writeMemory(final int startAddress, final byte[] data)
	{
		final byte[] mem = getDeviceMemory();
		for (int i = 0; i < data.length; i++) {
			final byte b = data[i];
			mem[startAddress + i] = b;
		}
		return new ServiceResult(data);
	}

	@Override
	public ServiceResult readAddress()
	{
		if (inProgrammingMode())
			return new ServiceResult(new byte[0]);
		return null;
	}

	@Override
	public ServiceResult readAddressSerial(final byte[] serialNo)
	{
		try {
			final byte[] myserial = device.getInterfaceObjectServer().getProperty(0,
					PID.SERIAL_NUMBER, 1, 1);
			if (Arrays.equals(myserial, serialNo)) {
				return new ServiceResult(new byte[0]);
			}
		}
		catch (final KNXPropertyException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public ServiceResult writeAddress(final IndividualAddress newAddress)
	{
		if (!inProgrammingMode())
			return null;
		final KNXMediumSettings settings = device.getDeviceLink().getKNXMedium();
		settings.setDeviceAddress(newAddress);
		return null;
	}

	@Override
	public ServiceResult writeAddressSerial(final byte[] serialNo,
		final IndividualAddress newAddress)
	{
		try {
			final byte[] myserial = device.getInterfaceObjectServer().getProperty(0,
					PID.SERIAL_NUMBER, 1, 1);
			if (Arrays.equals(myserial, serialNo)) {
				final KNXMediumSettings settings = device.getDeviceLink().getKNXMedium();
				settings.setDeviceAddress(newAddress);
			}
		}
		catch (final KNXPropertyException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public ServiceResult readDomainAddress()
	{
		if (inProgrammingMode())
			return new ServiceResult(domainAddress);
		return null;
	}

	@Override
	public ServiceResult readDomainAddress(final byte[] domain,
		final IndividualAddress startAddress, final int range)
	{
		if (Arrays.equals(domain, domainAddress)) {
			final int raw = device.getAddress().getRawAddress();
			final int start = startAddress.getRawAddress();
			if (raw >= start && raw <= (start + range)) {
				final int wait = (raw - start) * mediumTimeFactor;
				logger.trace("read domain address: wait " + wait + " ms before sending response");
				try {
					Thread.sleep(wait);
					return new ServiceResult(domainAddress);
				}
				catch (final InterruptedException e) {
					logger.warn("read domain address got interrupted, response is canceled");
					Thread.currentThread().interrupt();
				}
			}
		}
		return null;
	}

	@Override
	public ServiceResult writeDomainAddress(final byte[] domain)
	{
		if (inProgrammingMode()) {
			domainAddress = domain;
		}
		return null;
	}

	@Override
	public ServiceResult readDescriptor(final int type)
	{
		// by default, we only answer for descriptor type 0
		return type == 0 ? new ServiceResult(dd.toByteArray()) : null;
	}

	@Override
	public ServiceResult readADC(final int channel, final int consecutiveReads)
	{
		return new ServiceResult(new byte[] { (byte) channel, (byte) consecutiveReads, 0x1, 0x0 });
	}

	@Override
	public ServiceResult keyWrite(final int accessLevel, final byte[] key)
	{
		return new ServiceResult(new byte[] { (byte) accessLevel });
	}

	@Override
	public ServiceResult authorize(final byte[] key)
	{
		// possible access levels [max .. min]: [0 .. 3] or [0 .. 15]
		// clients with invalid auth always get minimum level 3/15
		final int levelInvalidAuth = 15;

		// choose the maximum access level an unauthorized client gets
		final int maxLevelNoAuth = 14;
		// the default auth key used for levels providing unauthorized access
		final byte[] defaultKey = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

		// XXX replaced with dummy value for porting to device package, make configurable
		final byte[] validKey = new byte[] { 0x10, 0x20, 0x30, 0x40 };
		final int levelValid = 2;

		int currentLevel = levelInvalidAuth;
		if (Arrays.equals(key, validKey))
			currentLevel = levelValid;
		else if (Arrays.equals(key, defaultKey))
			currentLevel = maxLevelNoAuth;

		return new ServiceResult(new byte[] { (byte) currentLevel });
	}

	@Override
	public ServiceResult restart(final boolean masterReset, final int eraseCode, final int channel)
	{
		logger.info("received request to restart");
		setProgrammingMode(false);
		return null;
	}

	@Override
	public ServiceResult management(final int svcType, final byte[] asdu)
	{
		logger.trace("management service " + DataUnitBuilder.decodeAPCI(svcType));
		return null;
	}
}
