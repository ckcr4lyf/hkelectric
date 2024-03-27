import { HKElectricApi } from "./api.js";

const api = new HKElectricApi(process.env.HKELECTRIC_USERNAME, process.env.HKELECTRIC_PASSWORD);
await api.login();
await api.getHalfHourlyLoadProfileTicket('20/03/2024');