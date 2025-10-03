import {execSync} from "child_process";
import * as fs from "fs";
import {basename, resolve,dirname,join}  from "path"
interface IContainer {
    size : number
    directory : string
    password: string
    locked : boolean
}

type ILuks              = Omit<IContainer, 'directory'>;
type IContainerSettings = Pick<IContainer, 'locked'>;

class Container {
    imagepath !: string
    id : string = '_.cipher.img'
    constructor(private config: IContainer) {
        this.id = `_.${basename(this.config.directory)}`
        this.imagepath = `${dirname(this.config.directory)}/${this.id}.img`

    }
    getSettings():IContainerSettings {
        try{
            return JSON.parse(fs.readFileSync(join(this.config.directory, "_.settings.json")).toString())
        }catch(e){
            return  {
                locked: false,
            }
        }
    }
    mount(){
        this.unmount();
        if(!fs.existsSync(this.config.directory))
            fs.mkdirSync(this.config.directory, { recursive: true });

        if(!fs.existsSync(dirname(this.imagepath)))
            fs.mkdirSync(dirname(this.imagepath),{recursive:true});

        if (!fs.existsSync(this.imagepath)) {
            try {
                execSync(`dd if=/dev/zero of=${this.imagepath} bs=1M count=${this.config.size}`);
            } catch (err) {
                console.error('Error creating disk image:', err);
            }

            try {
                execSync(`echo -n "${this.config.password}" | cryptsetup luksFormat ${this.imagepath} -q`, { stdio: 'inherit' });
            } catch (err) {
                console.error('Error formatting LUKS container:', err);
            }

            try {
                execSync(`echo -n "${this.config.password}" | cryptsetup luksOpen ${this.imagepath} ${this.id}`, { stdio: 'inherit' });
            } catch (err) {
                console.error('Error opening LUKS container:', err);
            }

            try {
                execSync(`mkfs.ext4 /dev/mapper/${this.id}`);
            } catch (err) {
                console.error('Error creating filesystem:', err);
            }

            try {
                execSync(`mount /dev/mapper/${this.id} ${this.config.directory}`);
            } catch (err) {
                console.error('Error mounting filesystem:', err);
            }

            try {
                fs.writeFileSync(join(this.config.directory, "_.settings.json"), JSON.stringify({
                    locked: this.config.locked
                }, null, 2));
            } catch (err) {
                console.error('Error writing settings file:', err);
            }

        } else {
            try {
                execSync(`echo -n "${this.config.password}" | cryptsetup luksOpen ${this.imagepath} ${this.id}`, { stdio: 'inherit' });
            } catch (err) {
                console.error('Error opening LUKS container:', err);
            }

            try {
                execSync(`mount /dev/mapper/${this.id} ${this.config.directory}`);
            } catch (err) {
                console.error('Error mounting filesystem:', err);
            }
        }


    }
    unmount(){
        try{
            execSync(`umount ${this.config.directory}`);
        }catch(e){}

        try {
            execSync(`cryptsetup luksClose ${this.id}`);
        }catch(e){}

        return this;
    }
    delete(){
        this.unmount()

        if(fs.existsSync(this.config.directory))
            fs.rmSync(this.config.directory, { recursive: true, force: true });

        if(fs.existsSync(this.imagepath))
            fs.unlinkSync(this.imagepath)

        return this;
    }
    resize(targetMB: number) {
        try {
            // Mount to check usage
            this.mount();
            const usedBytes = parseInt(execSync(`du -sb ${this.config.directory}`).toString().split(/\s+/)[0], 10);
            const usedMB = Math.ceil(usedBytes / (1024 * 1024));
            const bufferMB = 5;
            const minMB = usedMB + bufferMB;

            const diskInfo = execSync(`df -B1 ${this.imagepath} | tail -1`).toString().split(/\s+/);
            const freeBytes = parseInt(diskInfo[3], 10);
            const freeMB = Math.floor(freeBytes / (1024 * 1024));

            let finalMB = targetMB;
            if (targetMB < minMB) {
                console.warn(`Target size too small, resizing to minimum: ${minMB} MB`);
                finalMB = minMB;
            } else if (targetMB > freeMB) {
                throw new Error(`Target size ${targetMB} MB exceeds free disk space ${freeMB} MB`);
            }

            // Unmount
            execSync(`umount ${this.config.directory}`, { stdio: 'inherit' });

            // Check if shrinking or growing
            const currentSizeBytes = parseInt(execSync(`ls -l ${this.imagepath}`).toString().split(/\s+/)[4], 10);
            const currentSizeMB = Math.ceil(currentSizeBytes / (1024 * 1024));
            const isShrinking = finalMB < currentSizeMB;

            if (isShrinking) {
                execSync(`e2fsck -f /dev/mapper/${this.id}`, { stdio: 'inherit' });
                execSync(`resize2fs /dev/mapper/${this.id} ${finalMB}M`, { stdio: 'inherit' });
                execSync(`cryptsetup resize ${this.id}`, { stdio: 'inherit' });
                execSync(`truncate -s ${finalMB}M ${this.imagepath}`, { stdio: 'inherit' });
            } else {
                execSync(`truncate -s ${finalMB}M ${this.imagepath}`, { stdio: 'inherit' });
                execSync(`cryptsetup resize ${this.id}`, { stdio: 'inherit' });
                execSync(`e2fsck -f /dev/mapper/${this.id}`, { stdio: 'inherit' });
                execSync(`resize2fs /dev/mapper/${this.id} ${finalMB}M`, { stdio: 'inherit' });
            }

            // Close and reopen LUKS
            execSync(`cryptsetup close ${this.id}`, { stdio: 'inherit' });
            execSync(`cryptsetup luksOpen ${this.imagepath} ${this.id}`, { stdio: 'inherit' });
        } catch (e:any) {
            throw new Error(`Resize failed: ${e.message}`);
        }
    }

}

export class Luks {
    container !: Container;
    constructor(private directory :string,private config: ILuks) {
        this.container = new Container({...this.config,directory:this.directory});
    }
    // list containers
    static list(){
        let output = execSync(["lsblk -J | jq '[.blockdevices[]","  | select(.fstype == null and .children != null)" ,"  | {name: .name, uuid: .uuid, children: .children}]'"].join(' '))
        return JSON.parse(output.toString());
    }

    mount(){
        this.container.mount();
        return this;
    }
    unmount(){
        this.container.unmount();
        return this;
    }
    delete(force:boolean = false){
        if(!force)
        this.mount();
        if(this.container.getSettings()?.locked && !force)
            throw new Error(`The container is protected from deletion. Use force: true to override this protection. This safeguard prevents accidental deletions.`);

        this.container.delete();
        return this;
    }
    resize(size:number){
        this.container.resize(size);
    }
}


/*let directory : string
    = resolve(__dirname,'./vault/secrets');

let luks = new Luks(directory,{
    size     : 450,
    password : 'b1mujx22',
    locked   : true
});*/


// Luks list will output all containers in array
// Luks.list();
// will mount the luks container
// luks.mount();
// will unmont it
// luks.unmount();
// complete delete the container and data (if locked set to true, the method delete will fail if no argument force provided: delete(true))
// luks.delete(true/* true or false depend on locked property */);
// luks.resize(250)
