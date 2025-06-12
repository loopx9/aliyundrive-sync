import { Plugin, Notice, App, PluginSettingTab, Setting, TFile, TAbstractFile, setIcon, getIcon, requestUrl } from 'obsidian';
import { createHash } from 'crypto';

import * as path from 'path';

// 阿里云盘 SDK 类型定义
interface AliDriveFile {
	file_id: string;
	name: string;
	type: 'file' | 'folder';
	size?: number;
	parent_file_id: string;
	content_hash?: string;
	content_hash_name?: string;
	updated_at?: string;
}

interface AliDriveResponse<T> {
	items: T[];
	next_marker?: string;
}

interface PartInfo {
	part_number: number;
	upload_url: string;
}

interface AliDriveClient {
	listFiles: (parentId: string, marker?: string) => Promise<AliDriveResponse<AliDriveFile>>;
	uploadFile: (parentId: string, fileName: string, content: ArrayBuffer, oldFile?: AliDriveFile) => Promise<AliDriveFile>;
	downloadFile: (fileId: string) => Promise<ArrayBuffer>;
	createFolder: (parentId: string, folderName: string) => Promise<AliDriveFile>;
	deleteFile: (fileId: string) => Promise<void>;
	getRootFolder: () => Promise<AliDriveFile>;
	searchFile: (fileName: string, parentId?: string) => Promise<AliDriveFile | null>;
	getDriveId: () => Promise<string | null>;
	authorize: () => Promise<string | null>;
	renameFile: (fileId: string, newName: string) => Promise<any>;
	accessToken: string;
	plugin: AliSyncPlugin;
}

// 插件设置界面
interface AliSyncPluginSettings {
	accessToken: string;
	appKey: string;
	authCode: string;
	encryptionKey: string;
	encryptionIv: string;
	syncInterval: number;
	remoteFolderName: string;
	conflictResolution: string;
	lastSyncTime: number;
	chunkSize: number;
	overwriteExisting: boolean;
	enableRealTimeSync: boolean;
	syncRequestInterval: number;
}

const DEFAULT_SETTINGS: AliSyncPluginSettings = {
	accessToken: '',
	appKey: '55091393987b4cc090b090ee17e85e0a', //阿里云盘官方应用clientid
	authCode: '',
	encryptionKey: '',
	encryptionIv: '',
	syncInterval: 10,
	remoteFolderName: 'Obsidian',
	conflictResolution: 'local',
	lastSyncTime: 0,
	chunkSize: 10,
	overwriteExisting: true,
	enableRealTimeSync: true,
	syncRequestInterval: 1,
};

// 加密工具类
class EncryptionUtil {
	private static algorithm = 'AES-CBC';
	private static ivLength = 16;

	static async encryptBuffer(buffer: ArrayBuffer, key: string, _iv: string): Promise<ArrayBuffer> {
		const iv = new Uint8Array(Buffer.from(_iv, 'hex'));
		const cryptoKey = await this.importKey(key);

		const encrypted = await crypto.subtle.encrypt(
			{
				name: this.algorithm,
				iv: iv,
			},
			cryptoKey,
			buffer,
		);

		const result = new Uint8Array(iv.byteLength + encrypted.byteLength);
		result.set(new Uint8Array(iv), 0);
		result.set(new Uint8Array(encrypted), iv.byteLength);

		return result.buffer;
	}

	static async sha1ArrayBuffer(buffer: ArrayBuffer): Promise<string> {
		const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);

		//将哈希值转换为十六进制字符串
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

		return hashHex;
	}

	static async decryptBuffer(buffer: ArrayBuffer, key: string): Promise<ArrayBuffer> {
		const encryptedData = new Uint8Array(buffer);
		const iv = encryptedData.slice(0, this.ivLength);
		const data = encryptedData.slice(this.ivLength);

		const cryptoKey = await this.importKey(key);
		return crypto.subtle.decrypt(
			{
				name: this.algorithm,
				iv: iv,
			},
			cryptoKey,
			data,
		);
	}

	private static async importKey(key: string): Promise<CryptoKey> {
		const keyData = new TextEncoder().encode(key.padEnd(32, '\0').slice(0, 32));
		return crypto.subtle.importKey('raw', keyData, { name: this.algorithm }, false, ['encrypt', 'decrypt']);
	}
}

// 阿里云盘客户端实现
class AliDriveClientImpl implements AliDriveClient {
	accessToken: string;
	private settings: AliSyncPluginSettings;
	private baseUrl = 'https://openapi.alipan.com';
	private oauthUrl = 'https://openapi.aliyundrive.com/oauth/authorize';
	private tokenUrl = 'https://openapi.aliyundrive.com/oauth/access_token';
	private driverId: string;
	plugin: AliSyncPlugin;

	constructor(settings: AliSyncPluginSettings, plugin: AliSyncPlugin) {
		this.accessToken = settings.accessToken;
		this.settings = settings;
		this.plugin = plugin;
	}

	async authorize() {
		if (!this.settings.appKey) {
			new Notice('请先设置阿里云盘 App Key');
			return null;
		}

		// 构建授权 URL

		const authUrl = `${this.oauthUrl}?client_id=${this.settings.appKey}&redirect_uri=oob&scope=user:base,file:all:read,file:all:write&code_challenge=11111&code_challenge_method=plain`;

		// 打开授权页面
		if (this.settings.authCode == '') {
			window.open(authUrl, '_blank');
			return null;
		} else {
			try {
				// 获取访问令牌
				const tokenResponse = await requestUrl({
					url: this.tokenUrl,
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({
						grant_type: 'authorization_code',
						code: this.settings.authCode,
						client_id: this.settings.appKey,
						code_verifier: '11111',
					}),
				});

				const data = tokenResponse.json;
				this.settings.accessToken = data.access_token;
				this.settings.authCode = '';
				this.accessToken = data.access_token;

				// 获取 drive_id
				await this.getDriveId();

				new Notice('阿里云盘授权成功');
				return this.settings.accessToken;
			} catch (error) {
				console.error('阿里云盘授权失败', error);
				new Notice('阿里云盘授权失败: ' + error.message);
				return null;
			}
		}
	}

	private async request<T>(endpoint: string, body: any): Promise<T> {
		try {
			const response = await requestUrl({
				url: `${this.baseUrl}${endpoint}`,
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.accessToken}`,
				},
				body: JSON.stringify(body),
			});

			return response.json;
		} catch (error) {
			if (error.status === 401) {
				new Notice('阿里云盘令牌已失效,请重新授权: ' + error.message);
				this.plugin.isAuthorized = false;
				this.plugin.updateStatusBarText('阿里云盘: Token失效请重新授权', 'lucide-circle-x');
			}
			throw new Error(`请求url:${this.baseUrl}${endpoint}失败: ${error.message}`);
		}
	}

	async listFiles(parentId: string, marker?: string): Promise<AliDriveResponse<AliDriveFile>> {
		const body = {
			drive_id: this.driverId,
			parent_file_id: parentId,
			limit: 100,
			fields: '*',
			order_by: 'name',
			order_direction: 'ASC',
		};

		if (marker) {
			(body as any).marker = marker;
		}

		return this.request('/adrive/v1.0/openFile/list', body);
	}

	async uploadFile(parentId: string, fileName: string, content: ArrayBuffer, oldFile: AliDriveFile): Promise<AliDriveFile> {
		// 检查文件是否已存在

		if (oldFile) {
			const sha1_hash = await EncryptionUtil.sha1ArrayBuffer(content);
			//比较文件SHA1值, 相同则跳过
			if (oldFile.content_hash!.toLowerCase() === sha1_hash) {
				console.log(`${fileName} sync skipped (same SHA-1 hash)`);
				return oldFile;
			}
			await this.deleteFile(oldFile.file_id);
		}

		const chunkSize = this.settings.chunkSize * 100 * 1024; // 分片大小
		const partCount = Math.ceil(content.byteLength / chunkSize);

		// 1. 创建文件上传任务
		const createResponse = await this.request<{
			file_id: string;
			upload_id: string;
			part_info_list: PartInfo[];
		}>('/adrive/v1.0/openFile/create', {
			drive_id: this.driverId,
			parent_file_id: parentId,
			name: fileName,
			type: 'file',
			check_name_mode: 'ignore',
			size: content.byteLength,
			content_hash_name: 'sha1',
			proof_version: 'v1',
			proof_code: '',
			part_info_list: Array.from({ length: partCount }).map((_, index) => ({
				part_number: index + 1,
			})),
		});

		// 2. 分片上传
		for (let i = 0; i < partCount; i++) {
			const start = i * chunkSize;
			const end = Math.min((i + 1) * chunkSize, content.byteLength);
			const chunk = content.slice(start, end);

			const partInfo = createResponse.part_info_list.find((p) => p.part_number === i + 1);
			if (!partInfo) {
				throw new Error(`Missing upload URL for part ${i + 1}`);
			}

			await this.uploadChunk(chunk, partInfo.upload_url);
		}

		// 3. 完成上传
		const response = await this.request<AliDriveFile>('/adrive/v1.0/openFile/complete', {
			drive_id: this.driverId,
			file_id: createResponse.file_id,
			upload_id: createResponse.upload_id,
		});

		return {
			file_id: createResponse.file_id,
			name: fileName,
			type: 'file',
			parent_file_id: parentId,
			updated_at: response.updated_at,
		};
	}

	// 重命名文件
	async renameFile(fileId: string, newName: string): Promise<any> {
		try {
			// 重命名文件
			const response = await this.request('/adrive/v1.0/openFile/update', {
				drive_id: this.driverId,
				file_id: fileId,
				name: newName,
			});

			return response;
		} catch (error) {
			console.error('重命名文件失败', error);
			throw new Error('重命名文件失败: ' + error.message);
		}
	}

	private async uploadChunk(chunk: ArrayBuffer, uploadUrl: string): Promise<void> {
		try {
			await requestUrl({
				url: uploadUrl,
				method: 'PUT',
				body: chunk,
			});
		} catch (error) {
			throw new Error(`上传文件内容失败: ${error.message}`);
		}
	}

	async downloadFile(fileId: string): Promise<ArrayBuffer> {
		const response = await this.request<{ url: string }>('/adrive/v1.0/openFile/get', {
			drive_id: this.driverId,
			file_id: fileId,
		});

		const downloadResponse = await fetch(response.url);
		if (!downloadResponse.ok) {
			throw new Error('Failed to download file');
		}

		return downloadResponse.arrayBuffer();
	}

	async createFolder(parentId: string, folderName: string): Promise<AliDriveFile> {
		const folder = await this.request<AliDriveFile>('/adrive/v1.0/openFile/create', {
			drive_id: this.driverId,
			parent_file_id: parentId,
			name: folderName,
			type: 'folder',
			check_name_mode: 'refuse',
		});
		return {
			...folder,
			updated_at: new Date().toISOString(),
		};
	}

	async deleteFile(fileId: string): Promise<void> {
		await this.request('/adrive/v1.0/openFile/delete', {
			drive_id: this.driverId,
			file_id: fileId,
		});
	}

	async getRootFolder(): Promise<AliDriveFile> {
		return {
			file_id: 'root',
			name: 'root',
			type: 'folder',
			parent_file_id: '',
			updated_at: new Date().toISOString(),
		};
	}

	async searchFile(filePath: string): Promise<AliDriveFile | null> {
		const file_path = ('/' + filePath).replaceAll('/+', '/');
		const body: any = {
			drive_id: this.driverId,
			file_path: file_path,
		};
		try {
			const response = await this.request<AliDriveFile>('/adrive/v1.0/openFile/get_by_path', body);
			return response;
		} catch (error) {
			console.error('找不到文件:', file_path);
			return null;
		}
	}

	async getDriveId(): Promise<string | null> {
		try {
			const response = await requestUrl({
				url: `${this.baseUrl}/adrive/v1.0/user/getDriveInfo`,
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${this.accessToken}`,
				},
				body: JSON.stringify({}),
			});

			const data = response.json;
			this.driverId = data.default_drive_id;
			return data.default_drive_id;
		} catch (error) {
			console.error('获取drive_id失败:', error);
			return null;
		}
	}
}

interface QueueItem<T = any> {
	fn: (...args: any[]) => Promise<T>;
	args: any[];
	resolve: (value: T | PromiseLike<T>) => void;
	reject: (reason?: any) => void;
}

class ThrottleQueue {
	delay: number;
	forceStop = false;
	private queue: QueueItem[];
	private isProcessing: boolean;
	private lastExecuted: number;

	constructor(delay = 1000) {
		this.delay = delay;
		this.queue = [];
		this.isProcessing = false;
		this.lastExecuted = 0;
	}

	add<T>(fn: (...args: any[]) => Promise<T>, ...args: any[]): Promise<T> {
		return new Promise((resolve, reject) => {
			this.queue.push({ fn, args, resolve, reject });
			this.process();
		});
	}

	private async process(): Promise<void> {
		if (this.forceStop) {
			console.log(`syncQueue: ${this.queue.length} tasks cancled.`);
			this.clear();
			return;
		}

		if (this.isProcessing || this.queue.length === 0) return;

		this.isProcessing = true;
		const now = Date.now();
		const timeSinceLast = now - this.lastExecuted;
		const delay = Math.max(0, this.delay - timeSinceLast);

		setTimeout(async () => {
			const item = this.queue.shift()!;
			try {
				const result = await item.fn(...item.args);
				item.resolve(result);
			} catch (error) {
				item.reject(error);
			} finally {
				this.lastExecuted = Date.now();
				this.isProcessing = false;
				this.process();
			}
		}, delay);
	}

	clear(): void {
		this.queue = [];
	}
}

// 插件主类
export default class AliSyncPlugin extends Plugin {
	settings: AliSyncPluginSettings;
	aliClient: AliDriveClient | null = null;
	private syncIntervalId: number | null = null;
	remoteRootFolder: AliDriveFile | null = null;
	syncQueue: ThrottleQueue;
	private isSyncing = false;
	statusBarItem: HTMLElement;
	isAuthorized: boolean;
	app: App & { setting: any };

	async onload() {
		await this.loadSettings();
		this.statusBarItem = this.addStatusBarItem();

		//点击状态栏时打开插件设置页面
		this.statusBarItem.onclick = () => {
			const setting = this.app.setting;
			setting.open();
			setting.openTabById('aliyun-sync');
		};
		setIcon(this.statusBarItem, 'refresh-cw');
		this.addSettingTab(new AliSyncSettingTab(this.app, this));
		this.initializeAliClient();

		if (this.settings.accessToken) {
			try {
				const driverId = await this.aliClient!.getDriveId();
				if (driverId) {
					this.updateStatusBarText('阿里云盘: 通信正常', 'lucide-verified'); //lucide-circle-check-big
					this.isAuthorized = true;
					this.remoteRootFolder = await this.getOrCreateRemoteFolder();
				} else {
					this.updateStatusBarText('阿里云盘: Token失效请重新授权', 'lucide-circle-x');
					this.isAuthorized = false;
				}
			} catch (error) {
				console.error(error.message);
			}
		} else {
			this.updateStatusBarText('阿里云盘: 无Token请先授权', 'lucide-circle-x');
		}

		this.addCommand({
			id: 'ali-sync-now',
			name: 'Sync Now',
			callback: () => this.syncNow(),
		});

		if (this.settings.syncInterval > 0) {
			this.startSyncInterval();
		}

		//如果启用实时同步则注册事件监听文件修改
		if (this.settings.enableRealTimeSync) {
			this.syncQueue = new ThrottleQueue(this.settings.syncRequestInterval * 1000);
		} else {
			//默认节流队列执行间隔时间: 1000毫秒
			this.syncQueue = new ThrottleQueue(1000);
		}

		//注册文件状态监控事件
		this.registerFileWatchers();

		// 在侧边栏添加图标
		this.addRibbonIcon('folder-sync', '开始同步', () => {
			this.syncNow();
		});

		console.log('AliDrive Sync Plugin loaded');
	}

	onunload() {
		if (this.syncIntervalId) {
			window.clearInterval(this.syncIntervalId);
		}

		console.log('AliDrive Sync Plugin unloaded');
	}

	private initializeAliClient() {
		this.aliClient = new AliDriveClientImpl(this.settings, this);
	}

	startSyncInterval() {
		if (this.syncIntervalId) {
			window.clearInterval(this.syncIntervalId);
		}
		this.syncIntervalId = window.setInterval(() => this.syncNow(), this.settings.syncInterval * 60 * 1000);
	}

	registerFileWatchers() {
		this.registerEvent(this.app.vault.on('create', (file) => this.settings.enableRealTimeSync && this.handleFileChange(file)));

		this.registerEvent(this.app.vault.on('modify', (file) => this.settings.enableRealTimeSync && this.handleFileChange(file)));

		this.registerEvent(this.app.vault.on('delete', (file) => this.settings.enableRealTimeSync && this.handleFileDelete(file)));

		this.registerEvent(this.app.vault.on('rename', (file, oldPath) => this.settings.enableRealTimeSync && this.handleFileRename(file, oldPath)));
	}

	private handleFileChange(file: TAbstractFile) {
		if (file instanceof TFile && this.isAuthorized) {
			const filepath = file.path.replaceAll(/^\/+/gs, '');
			this.syncQueue.add(this.syncFileToRemote, file, this);
			console.log(`File change detected: ${filepath}`);
		}
	}

	private async handleFileDelete(file: TAbstractFile) {
		if (!this.aliClient || !this.isAuthorized || !this.remoteRootFolder) {
			return;
		}

		this.syncQueue.add(this.deleteRemoteFile, file, this);

		console.log(`Deleted remote file: ${file.path}`);
	}

	private async handleFileRename(file: TAbstractFile, oldPath: string) {
		if (!this.aliClient || !this.isAuthorized || !this.remoteRootFolder) {
			return;
		}

		this.syncQueue.add(this.renameRemoteFile, file, oldPath, this);
	}

	private async renameRemoteFile(file: TFile, oldPath: string, plugin: AliSyncPlugin) {
		if (!plugin.aliClient || !plugin.isAuthorized || !plugin.remoteRootFolder) {
			return;
		}
		try {
			const oldRemoteFile = await plugin.aliClient.searchFile((plugin.settings.remoteFolderName + '/' + oldPath).replaceAll('/+', '/'));
			if (oldRemoteFile) {
				console.log(`Handled file rename from ${oldPath} to ${file.path}`);
				await plugin.aliClient.renameFile(oldRemoteFile.file_id, file.name);
				return;
			}

			console.log(`${oldPath} not exists on remote`);
			await plugin.syncFileToRemote(file, plugin);
		} catch (error) {
			console.error(`Failed to handle rename for ${oldPath} to ${file.path}:`, error);
		}
	}

	private async syncFileToRemote(file: TFile, plugin: AliSyncPlugin) {
		if (!plugin.aliClient || !plugin.isAuthorized || !plugin.remoteRootFolder) {
			return;
		}

		try {
			const fileContent = await plugin.app.vault.readBinary(file);
			const encryptedContent = plugin.settings.encryptionKey ? await EncryptionUtil.encryptBuffer(fileContent, plugin.settings.encryptionKey, plugin.settings.encryptionIv) : fileContent;
			const sha1_hash = await EncryptionUtil.sha1ArrayBuffer(encryptedContent);

			const localModified = (await plugin.app.vault.adapter.stat(file.path))!.mtime;

			const remoteFile = await plugin.aliClient.searchFile((plugin.settings.remoteFolderName + '/' + file.path).replaceAll('/+', '/'));

			if (plugin.settings.overwriteExisting || !remoteFile || localModified > new Date(remoteFile.updated_at || 0).getTime()) {
				if (remoteFile) {
					//比较文件SHA1值, 相同则跳过
					if (remoteFile.content_hash!.toLowerCase() === sha1_hash) {
						console.log(`${file.path} sync skipped (same SHA-1 hash)`);
						return;
					}

					//如果远端存在文件则先删除后上传
					await plugin.aliClient.uploadFile(remoteFile.parent_file_id, file.name, encryptedContent, remoteFile);
				} else {
					const remoteParentId = await plugin.mkdirs(file.path);
					await plugin.aliClient.uploadFile(remoteParentId, file.name, encryptedContent);
				}

				console.log(`Synced file to remote: ${file.path}`);
			}
		} catch (error) {
			console.error(`Failed to sync file ${file.path}:`, error);
			throw error;
		}
	}

	private async deleteRemoteFile(file: TFile, plugin: AliSyncPlugin) {
		if (!plugin.aliClient || !plugin.isAuthorized || !plugin.remoteRootFolder) {
			return;
		}

		try {
			const remoteFile = await plugin.aliClient.searchFile((plugin.settings.remoteFolderName + '/' + file.path).replaceAll('\\', '/').replaceAll('/+', '/'));
			if (remoteFile) {
				await plugin.aliClient.deleteFile(remoteFile.file_id);
				console.log(`remote file ${file.path} deleted`);
			}
		} catch (error) {
			console.error(`Failed to delete remote file ${file.path}:`, error);
		}
	}

	async syncNow() {
		if (!this.aliClient || !this.isAuthorized) {
			new Notice('AliDrive client not initialized. Please check your access token.');
			return;
		}

		try {
			new Notice('Starting sync with AliDrive...');
			await this.performSync();

			this.settings.lastSyncTime = Date.now();
			await this.saveSettings();

			new Notice('Sync completed successfully!');
			this.updateStatusBarText('阿里云盘: 同步完成', 'lucide-circle-check-big');
		} catch (error) {
			console.error('Sync error:', error);
			new Notice(`Sync failed: ${error.message}`);
		}
	}

	async getOrCreateRemoteFolder(): Promise<AliDriveFile> {
		if (!this.aliClient || !this.isAuthorized) {
			throw new Error('AliDrive client not initialized');
		}

		const root = await this.aliClient.getRootFolder();
		let folder = await this.aliClient.searchFile(this.settings.remoteFolderName);

		if (!folder) {
			folder = await this.aliClient.createFolder(root.file_id, this.settings.remoteFolderName);
		}

		return folder;
	}

	//逐级创建文件夹
	private async mkdirs(filepath: string): Promise<string> {
		if (!this.aliClient || !this.isAuthorized) {
			throw new Error('AliDrive client not initialized');
		}

		const dirs = filepath.split('/').filter((v) => v);
		const rootFolder = await this.getOrCreateRemoteFolder();
		if (dirs.length > 1) {
			let currentPath = '';
			let parentId = rootFolder.file_id;
			for (let i = 0; i < dirs.length - 1; i++) {
				currentPath += '/' + dirs[i];
				const remotepath = (this.settings.remoteFolderName + currentPath).replaceAll('/+', '/');

				//判断文件夹是否存在
				let folder = await this.aliClient.searchFile(remotepath);

				if (!folder) {
					folder = await this.aliClient.createFolder(parentId, dirs[i]);
					parentId = folder.file_id;

					//其余下级文件夹直接创建不需要判断是否存在
					for (let j = i + 1; j < dirs.length - 1; j++) {
						folder = await this.aliClient.createFolder(parentId, dirs[j]);
						parentId = folder.file_id;
					}
					return parentId;
				}
				parentId = folder.file_id;
			}

			return parentId;
		}
		return rootFolder.file_id;
	}

	private async performSync() {
		if (!this.aliClient || !this.isAuthorized || !this.remoteRootFolder) {
			throw new Error('AliDrive client or remote folder not initialized');
		}

		this.updateStatusBarText('阿里云盘: 上传中...', 'lucide-cloud-upload');
		await this.syncLocalToRemote();
		this.updateStatusBarText('阿里云盘: 下载中...', 'lucide-cloud-download');
		await this.syncRemoteToLocal('/', this.remoteRootFolder.file_id);
	}

	private async syncLocalToRemote() {
		if (!this.aliClient || !this.isAuthorized) {
			throw new Error('AliDrive client not initialized');
		}

		const files = this.app.vault.getFiles();

		for (const file of files) {
			const fileRelativePath = (this.settings.remoteFolderName + '/' + file.path).replaceAll('/+', '/');
			const remoteFile = await this.aliClient.searchFile(fileRelativePath);

			const fileContent = await this.app.vault.adapter.readBinary(file.path);
			const encryptedContent = this.settings.encryptionKey ? await EncryptionUtil.encryptBuffer(fileContent, this.settings.encryptionKey, this.settings.encryptionIv) : fileContent;

			const localModified = file.stat.mtime;

			if (remoteFile) {
				const remoteModified = new Date(remoteFile.updated_at || 0).getTime();

				// 基于时间的同步决策,本地文件新修改则覆盖上传
				if (localModified > remoteModified) {
					console.log(`Updated remote file (newer local): ${fileRelativePath}`);
					await this.aliClient.uploadFile(remoteFile.parent_file_id, file.name, encryptedContent, remoteFile);
				}
			} else {
				console.log(`Uploaded new file to remote: ${fileRelativePath}`);
				const remoteParentId = await this.mkdirs(file.path);
				await this.aliClient.uploadFile(remoteParentId, file.name, encryptedContent);
			}
		}
	}

	private async syncRemoteToLocal(localPath: string, remoteParentId: string, relativePath = '') {
		if (!this.aliClient || !this.isAuthorized) {
			throw new Error('AliDrive client not initialized');
		}

		let marker: string | undefined;
		let remoteFiles: AliDriveFile[] = [];

		do {
			const response = await this.aliClient.listFiles(remoteParentId, marker);
			remoteFiles = remoteFiles.concat(response.items);
			marker = response.next_marker;
		} while (marker);

		for (const remoteFile of remoteFiles) {
			const fileRelativePath = path.join(relativePath, remoteFile.name).replaceAll('\\', '/').replaceAll('//', '/');
			const localFilePath = path.join(localPath, remoteFile.name).replaceAll('\\', '/').replaceAll('//', '/');

			if (remoteFile.type === 'file') {
				try {
					const localExists = await this.app.vault.adapter.exists(localFilePath);
					const remoteModified = new Date(remoteFile.updated_at || 0).getTime();

					if (localExists) {
						const localStat = await this.app.vault.adapter.stat(localFilePath);
						const localModified = localStat!.mtime;

						switch (this.settings.conflictResolution) {
							case 'newest':
								if (remoteModified > localModified) {
									await this.downloadAndSaveFile(remoteFile, localFilePath, fileRelativePath);
								}
								break;

							case 'newest-keep':
								if (remoteModified > localModified) {
									const backupPath = localFilePath + `.backup_${localModified}`;
									const localContent = await this.app.vault.adapter.readBinary(localFilePath);
									await this.app.vault.adapter.writeBinary(backupPath, localContent);
									await this.downloadAndSaveFile(remoteFile, localFilePath, fileRelativePath);
									console.log(`Updated file keeping backup: ${fileRelativePath}`);
								} else if (remoteModified < localModified) {
									const backupPath = localFilePath + `.remote_backup_${remoteModified}`;
									await this.downloadAndSaveFile(remoteFile, backupPath, fileRelativePath + '.remote_backup');
								}
								break;

							case 'remote':
								await this.downloadAndSaveFile(remoteFile, localFilePath, fileRelativePath);
								break;

							case 'local':
								break;

							case 'both':
								if (remoteModified !== localModified) {
									const conflictPath = localFilePath + `.conflict_${remoteModified}`;
									await this.downloadAndSaveFile(remoteFile, conflictPath, fileRelativePath + '.conflict');
								}
								break;
						}
					} else {
						await this.downloadAndSaveFile(remoteFile, localFilePath, fileRelativePath);
					}
				} catch (error) {
					console.error(`Failed to sync remote file ${fileRelativePath}:`, error);
				}
			} else if (remoteFile.type === 'folder') {
				const localExists = await this.app.vault.adapter.exists(localFilePath);

				if (!localExists) {
					await this.app.vault.adapter.mkdir(localFilePath);
					console.log(`Created local folder: ${fileRelativePath}`);
				}

				await this.syncRemoteToLocal(localFilePath, remoteFile.file_id, fileRelativePath);
			}
		}
	}

	private async downloadAndSaveFile(remoteFile: AliDriveFile, localPath: string, relativePath: string) {
		if (!this.aliClient || !this.isAuthorized) {
			throw new Error('AliDrive client not initialized');
		}

		const encryptedContent = await this.aliClient.downloadFile(remoteFile.file_id);
		const fileContent = encryptedContent;
		try {
			const fileContent = this.settings.encryptionKey ? await EncryptionUtil.decryptBuffer(encryptedContent, this.settings.encryptionKey) : encryptedContent;
		} catch (error) {
			console.error(`failed to decrypt: ${localPath}`);
			//const fileContent = encryptedContent;
		}

		await this.app.vault.adapter.writeBinary(localPath, new Uint8Array(fileContent));
		console.log(`Downloaded remote file: ${relativePath}`);
	}

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

	updateStatusBarText(text: string, icon: string) {
		if (this.statusBarItem) {
			const span = this.statusBarItem.querySelector('span');
			if (span != null) {
				span.setText(text);
			} else {
				this.statusBarItem.createEl('span', {
					text: text,
				});
			}

			this.statusBarItem.querySelector('svg')!.innerHTML = getIcon(icon)!.innerHTML;
		}
	}
}

// 设置选项卡
class AliSyncSettingTab extends PluginSettingTab {
	plugin: AliSyncPlugin;

	constructor(app: App, plugin: AliSyncPlugin) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display(): void {
		const { containerEl } = this;

		containerEl.empty();
		containerEl.createEl('h2', { text: 'AliDrive Sync Settings' });

		const accessToken = new Setting(containerEl)
			.setName('AliDrive Access Token')
			.setDesc('Your AliDrive API access token')
			.addText((text) =>
				text
					.setPlaceholder('Enter your access token')
					.setValue(this.plugin.settings.accessToken)
					.onChange(async (value) => {
						this.plugin.settings.accessToken = value;
						this.plugin.aliClient!.accessToken = value;
						await this.plugin.saveSettings();
					}),
			);

		// App Key
		new Setting(containerEl)
			.setName('App Key')
			.setDesc('阿里云盘应用的 App Key')
			.addText((text) =>
				text
					.setPlaceholder('输入 App Key')
					.setValue(this.plugin.settings.appKey)
					.onChange(async (value) => {
						this.plugin.settings.appKey = value;
						await this.plugin.saveSettings();
					}),
			);

		// auth code
		const authCode = new Setting(containerEl)
			.setName('AuthCode')
			.setDesc('阿里云盘授权码')
			.addText((text) =>
				text
					.setPlaceholder('输入 授权码')
					.setValue(this.plugin.settings.authCode)
					.onChange(async (value) => {
						this.plugin.settings.authCode = value;
					}),
			);

		// 授权按钮
		new Setting(containerEl)
			.setName('阿里云盘授权')
			.setDesc('点击授权访问阿里云盘')
			.addButton((button) =>
				button.setButtonText('授权').onClick(async () => {
					const token = await this.plugin.aliClient!.authorize();
					authCode.settingEl.querySelector('input')!.value = '';
					this.plugin.settings!.authCode = '';
					if (token) {
						accessToken.settingEl.querySelector('input')!.value = token;
						this.plugin.isAuthorized = true;
						this.plugin.updateStatusBarText('阿里云盘: 通信正常', 'lucide-circle-check-big');
						this.plugin.remoteRootFolder = await this.plugin.getOrCreateRemoteFolder();
					}
					await this.plugin.saveSettings();
				}),
			);

		const o = new Setting(containerEl)
			.setName('Encryption Key')
			.setDesc('Key used to encrypt files before uploading (leave empty for no encryption)')
			.addText((text) => {
				(text.inputEl.type = 'password'),
					text
						.setPlaceholder('Enter encryption key')
						.setValue(this.plugin.settings.encryptionKey)
						.onChange(async (value) => {
							this.plugin.settings.encryptionKey = value;

							//IV关联key,截取其SHA-256的其中32位字节，固定使用，方便比对文件SHA1判断文件内容是否发生变化
							this.plugin.settings.encryptionIv = createHash('sha256').update(value).digest('hex').slice(30, 62).toUpperCase();
							await this.plugin.saveSettings();
						});
			});
		o.addExtraButton((r) => {
			r.setIcon('eye')
				.setTooltip('显示密码')
				.onClick(() => {
					const a = o.controlEl.querySelector('input');
					a && (a.type === 'password' ? ((a.type = 'text'), r.setIcon('eye-off'), r.setTooltip('隐藏')) : ((a.type = 'password'), r.setIcon('eye'), r.setTooltip('显示密码')));
				});
		});

		new Setting(containerEl)
			.setName('Sync Interval (minutes)')
			.setDesc('Set to 0 to disable automatic syncing')
			.addSlider((slider) =>
				slider
					.setLimits(0, 240, 1)
					.setValue(this.plugin.settings.syncInterval)
					.onChange(async (value) => {
						this.plugin.settings.syncInterval = value;
						await this.plugin.saveSettings();
						if (value > 0) {
							this.plugin.startSyncInterval();
						}
					})
					.setDynamicTooltip(),
			);

		new Setting(containerEl)
			.setName('Remote Folder Name')
			.setDesc('Name of the folder in AliDrive where your vault will be synced')
			.addText((text) =>
				text
					.setPlaceholder('Enter folder name')
					.setValue(this.plugin.settings.remoteFolderName)
					.onChange(async (value) => {
						this.plugin.settings.remoteFolderName = value;
						await this.plugin.saveSettings();
					}),
			);

		new Setting(containerEl)
			.setName('Conflict Resolution')
			.setDesc('How to handle file conflicts when downloading')
			.addDropdown((dropdown) =>
				dropdown
					.addOption('newest', 'Newest version wins (by modify time)')
					.addOption('newest-keep', 'Newest wins, keep old version')
					.addOption('remote', 'Remote wins always')
					.addOption('local', 'Local wins always')
					.addOption('both', 'Keep both (create conflict file)')
					.setValue(this.plugin.settings.conflictResolution)
					.onChange(async (value) => {
						this.plugin.settings.conflictResolution = value;
						await this.plugin.saveSettings();
					}),
			);

		new Setting(containerEl)
			.setName('Upload Chunk Size (MB)')
			.setDesc('Size of each chunk for large file uploads')
			.addSlider((slider) =>
				slider
					.setLimits(5, 100, 5)
					.setValue(this.plugin.settings.chunkSize)
					.onChange(async (value) => {
						this.plugin.settings.chunkSize = value;
						await this.plugin.saveSettings();
					})
					.setDynamicTooltip(),
			);

		new Setting(containerEl)
			.setName('Overwrite Existing Files')
			.setDesc('Always overwrite remote files when uploading (ignore modification time)')
			.addToggle((toggle) =>
				toggle.setValue(this.plugin.settings.overwriteExisting).onChange(async (value) => {
					this.plugin.settings.overwriteExisting = value;
					await this.plugin.saveSettings();
				}),
			);

		new Setting(containerEl)
			.setName('Real-time File Sync request interval(seconds)')
			.setDesc('Automatic File sync request interval. Set to 0 to disable.')
			.addSlider((slider) =>
				slider
					.setLimits(0, 10, 0.5)
					.setValue(this.plugin.settings.syncRequestInterval)
					.onChange(async (value) => {
						this.plugin.settings.syncRequestInterval = value;
						if (value > 0) {
							//更新实时同步启用标志
							this.plugin.settings.enableRealTimeSync = true;
							this.plugin.syncQueue.forceStop = false;
							//更新队列执行时间间隔
							this.plugin.syncQueue.delay = value * 1000;
							console.log('Real-time sync enabled');
						} else {
							console.log('Real-time sync disabled');
							this.plugin.settings.enableRealTimeSync = false;

							//强制清空同步队列
							this.plugin.syncQueue.forceStop = true;
						}
						await this.plugin.saveSettings();
					})
					.setDynamicTooltip(),
			);

		new Setting(containerEl).addButton((button) =>
			button.setButtonText('Sync Now').onClick(() => {
				this.plugin.syncNow();
			}),
		);
	}
}
