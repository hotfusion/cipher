import {execSync} from "child_process";
import * as fs from "fs";
import {basename, resolve,dirname,join}  from "path"
import {config} from "winston";
interface IContainer {
    size : number
    directory : string
    password: string
    locked : boolean
}

type ILuks              = Omit<IContainer, 'directory'>;
type IContainerSettings = Pick<IContainer, 'locked'>;

//


class Container {
    imagepath !: string
    id : string = '_.cipher.img'
    constructor(private config: IContainer) {
        this.id = `_.${basename(this.config.directory)}`
        this.imagepath = `${dirname(this.config.directory)}/${this.id}.img`

    }
    getSettings():IContainerSettings {
        return JSON.parse(fs.readFileSync(join(this.config.directory, "_.settings.json")).toString())
    }
    mount(){
        this.unmount();
        if(!fs.existsSync(this.config.directory))
            fs.mkdirSync(this.config.directory, { recursive: true });

        if(!fs.existsSync(dirname(this.imagepath)))
            fs.mkdirSync(dirname(this.imagepath),{recursive:true});

        if(!fs.existsSync(this.imagepath)) {
            execSync(`dd if=/dev/zero of=${this.imagepath} bs=1M count=${this.config.size}`);
            execSync(`echo -n "${this.config.password}" | cryptsetup luksFormat ${this.imagepath} -q`, {stdio: 'inherit'});
            execSync(`echo -n "${this.config.password}" | cryptsetup luksOpen ${this.imagepath} ${this.id}`, { stdio: 'inherit' });
            execSync(`mkfs.ext4 /dev/mapper/${this.id}`)
            execSync(`mount /dev/mapper/${this.id} ${this.config.directory}`);

            fs.writeFileSync(join(this.config.directory, "_.settings.json"), JSON.stringify({
                locked : this.config.locked
            }, null, 2));
        }else {
            execSync(`echo -n "${this.config.password}" | cryptsetup luksOpen ${this.imagepath} ${this.id}`, {stdio: 'inherit'});
            execSync(`mount /dev/mapper/${this.id} ${this.config.directory}`);
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
        try{
            execSync(`umount ${this.config.directory}`, { stdio: 'ignore' })
        }catch(e){}

        try{
            execSync(`cryptsetup luksClose ${this.id}`, { stdio: 'ignore' });
        }catch(e){}

        if(fs.existsSync(this.config.directory))
            fs.rmSync(this.config.directory, { recursive: true, force: true });

        if(fs.existsSync(this.imagepath))
            fs.unlinkSync(this.imagepath)

        return this;
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
        this.mount();
        if(this.container.getSettings().locked && !force)
            throw new Error(`Container is protected from deletion`);

        this.container.delete();
        return this;
    }
}

let directory : string
    = resolve(__dirname,'./store/mySecretFolder');

new Luks(directory,{
    size     : 100,
    password : 'b1mujx22',
    locked   : true
}).delete().mount()


//console.log(Luks.list());