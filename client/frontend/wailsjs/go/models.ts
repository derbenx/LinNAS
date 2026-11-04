export namespace main {

	export class ClientConfig {
	    server_endpoint: string;
	    username: string;
	    password_hash: string;
	    session_token?: string;
	    local_sync_dir: string;
	    sync_enabled: boolean;
	    sync_mode: string;
	    sync_interval_sec: number;
	    throttle_kbps: number;
	    idle_only: boolean;
	    selected_folders: Record<string, boolean>;
	    log_to_file: boolean;

	    static createFrom(source: any = {}) {
	        return new ClientConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server_endpoint = source["server_endpoint"];
	        this.username = source["username"];
	        this.password_hash = source["password_hash"];
	        this.session_token = source["session_token"];
	        this.local_sync_dir = source["local_sync_dir"];
	        this.sync_enabled = source["sync_enabled"];
	        this.sync_mode = source["sync_mode"];
	        this.sync_interval_sec = source["sync_interval_sec"];
	        this.throttle_kbps = source["throttle_kbps"];
	        this.idle_only = source["idle_only"];
	        this.selected_folders = source["selected_folders"];
	        this.log_to_file = source["log_to_file"];
	    }
	}
	export class SmartDiskInfo {
	    device: string;
	    part_label?: string;
	    first_part_name?: string;
	    model: string;
	    serial?: string;
	    capacity: string;
	    health: string;
	    temp_c?: number;
	    hostname?: string;
	    ip?: string;
	    raw_info?: string;

	    static createFrom(source: any = {}) {
	        return new SmartDiskInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device = source["device"];
	        this.part_label = source["part_label"];
	        this.first_part_name = source["first_part_name"];
	        this.model = source["model"];
	        this.serial = source["serial"];
	        this.capacity = source["capacity"];
	        this.health = source["health"];
	        this.temp_c = source["temp_c"];
	        this.hostname = source["hostname"];
	        this.ip = source["ip"];
	        this.raw_info = source["raw_info"];
	    }
	}
	export class ClientGroupInfo {
	    ip: string;
	    client: string;
	    disks: SmartDiskInfo[];

	    static createFrom(source: any = {}) {
	        return new ClientGroupInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.client = source["client"];
	        this.disks = this.convertValues(source["disks"], SmartDiskInfo);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CombinedSmartData {
	    overall_healthy: boolean;
	    is_test: boolean;
	    server_disks: SmartDiskInfo[];
	    local_disks: SmartDiskInfo[];
	    client_groups: ClientGroupInfo[];
	    error?: string;

	    static createFrom(source: any = {}) {
	        return new CombinedSmartData(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.overall_healthy = source["overall_healthy"];
	        this.is_test = source["is_test"];
	        this.server_disks = this.convertValues(source["server_disks"], SmartDiskInfo);
	        this.local_disks = this.convertValues(source["local_disks"], SmartDiskInfo);
	        this.client_groups = this.convertValues(source["client_groups"], ClientGroupInfo);
	        this.error = source["error"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ServerItem {
	    name: string;
	    rel_path: string;
	    is_dir: boolean;
	    size: number;
	    mod_time: number;
	    sha256?: string;

	    static createFrom(source: any = {}) {
	        return new ServerItem(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.rel_path = source["rel_path"];
	        this.is_dir = source["is_dir"];
	        this.size = source["size"];
	        this.mod_time = source["mod_time"];
	        this.sha256 = source["sha256"];
	    }
	}

}
