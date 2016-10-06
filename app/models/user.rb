class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  attr_accessible :nombre, :nacionalidad, :dia, :mes, :ano, :nombre_perfil,
  				  :email, :encrypted_password
end
